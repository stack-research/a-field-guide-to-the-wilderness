from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import tomllib
import unicodedata
import xml.etree.ElementTree as ET

from wilderness.common import (
    TEXT_EXTENSIONS,
    has_control_chars,
    is_likely_binary,
    read_bytes,
    reset_directory,
    safe_display,
    sha256_bytes,
    sha256_directory,
    sha256_file,
)
from wilderness.intake import IntakeRecord
from wilderness.policy import Policy
from wilderness.redact import redact_bytes
from wilderness.unpack import UnpackResult

SUPPORTED_MANIFEST_NAMES = {
    "manifest.json",
    "manifest.toml",
    "provenance.json",
}
MANIFEST_SCHEMA_VERSION = 1
_MANIFEST_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_SOURCE_KINDS = {"file", "directory"}
_SUSPICIOUS_TEXT_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL
SUSPICIOUS_TEXT_NORMALIZATION_VERSION = "1"
_BUILTIN_EXCLUDE_PATTERN = (
    r"\b(do not|does not|don't|never|avoid|avoids|without|example|examples|documentation|docs|describes?|explains?)\b"
)
_BUILTIN_RULE_DEFS = (
    {
        "id": "ignore_prior_instructions",
        "pattern": r"\b(ignore|disregard|forget)\b[\s\S]{0,48}\b(previous|prior|earlier|above)\b[\s\S]{0,24}\b(instructions?|guidance|directions?|messages?)\b",
        "description": "instruction override language",
    },
    {
        "id": "role_confusion_request",
        "pattern": r"(\b(ignore|override|replace|act as|you are now)\b[\s\S]{0,48}\b(system|developer|hidden)\b[\s\S]{0,24}\b(messages?|instructions?|prompts?)\b|\b(system|developer|hidden)\b[\s\S]{0,32}\b(messages?|instructions?|prompts?)\b[\s\S]{0,48}\b(ignore|override|replace|act as|you are now)\b)",
        "description": "role or instruction hierarchy confusion",
        "exclude_pattern": _BUILTIN_EXCLUDE_PATTERN,
    },
    {
        "id": "system_prompt_reference",
        "pattern": r"(\b(reveal|show|print|dump|expose)\b[\s\S]{0,40}\b(system prompt|developer message|hidden instructions|prompt)\b|\b(system prompt|developer message|hidden instructions)\b[\s\S]{0,40}\b(reveal|show|print|dump|expose)\b)",
        "description": "attempt to expose hidden prompt material",
        "exclude_pattern": _BUILTIN_EXCLUDE_PATTERN,
    },
    {
        "id": "tool_execution_request",
        "pattern": r"(\brun this command\b|\bexecute (this|the|following)? ?command\b|\b(download|fetch|run|execute|use)\b[\s\S]{0,48}\b(curl|wget|powershell|bash|sh|script)\b|\b(curl|wget|powershell|bash|sh|script)\b[\s\S]{0,48}\b(download|fetch|run|execute|use)\b)",
        "description": "tooling or command execution request",
        "exclude_pattern": _BUILTIN_EXCLUDE_PATTERN,
    },
    {
        "id": "credential_request",
        "pattern": r"\b(print|reveal|show|dump|share|send|expose)\b[\s\S]{0,48}\b(token|api key|password|secret|credential)\b",
        "description": "credential disclosure request",
        "exclude_pattern": _BUILTIN_EXCLUDE_PATTERN,
    },
    {
        "id": "data_exfiltration_request",
        "pattern": r"\b(upload|send|print|dump|expose|share)\b[\s\S]{0,64}\b(local files?|workspace|environment variables?|env vars?|secrets?)\b",
        "description": "local data exfiltration request",
        "exclude_pattern": _BUILTIN_EXCLUDE_PATTERN,
    },
)


@dataclass(frozen=True, slots=True)
class SuspiciousTextRule:
    rule_id: str
    pattern: re.Pattern[str]
    description: str | None = None
    exclude_pattern: re.Pattern[str] | None = None
    window_lines: int | None = None
    source: str = "builtin"
    pack_path: str | None = None
    pack_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class SuspiciousTextPack:
    path: str
    sha256: str
    rule_count: int


@dataclass(frozen=True, slots=True)
class SuspiciousTextRuleSet:
    enabled: bool
    normalization_version: str
    builtin_rule_count: int
    loaded_packs: tuple[SuspiciousTextPack, ...]
    rules: tuple[SuspiciousTextRule, ...]

    @property
    def rule_count(self) -> int:
        if not self.enabled:
            return 0
        return len(self.rules)


@dataclass(frozen=True, slots=True)
class SuspiciousTextScanResult:
    findings: tuple[dict, ...]
    suppressed_matches: tuple[dict, ...]


@dataclass(frozen=True, slots=True)
class ParsedManifest:
    path: str
    schema_version: int | None
    claims: dict
    validated: bool
    findings: tuple[dict, ...]


def _finding(
    family: str,
    severity: str,
    message: str,
    path: str | None = None,
    **extra: str | int,
) -> dict:
    finding = {"family": family, "severity": severity, "message": message}
    if path is not None:
        finding["path"] = path
    finding.update(extra)
    return finding


def _is_supported_manifest(path: Path) -> bool:
    return path.name.lower() in SUPPORTED_MANIFEST_NAMES


def _parse_manifest(path: Path, data: bytes) -> tuple[dict | None, dict | None]:
    lower_name = path.name.lower()
    try:
        if lower_name in {"manifest.json", "provenance.json"}:
            manifest = json.loads(data.decode("utf-8"))
        elif lower_name == "manifest.toml":
            manifest = tomllib.loads(data.decode("utf-8"))
        else:
            return None, _finding("schema_violation", "moderate", "manifest format unsupported", str(path))
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        return None, _finding("schema_violation", "severe", f"manifest parse failed: {error}", str(path))
    if not isinstance(manifest, dict):
        return None, _finding("schema_violation", "severe", "manifest top level must be an object", str(path))
    return manifest, None


def _parse_manifest_schema(path: Path, manifest: dict) -> ParsedManifest:
    findings: list[dict] = []
    claims: dict[str, str | int] = {}
    schema_version = manifest.get("schema_version")
    if type(schema_version) is int and schema_version == MANIFEST_SCHEMA_VERSION:
        normalized_schema_version: int | None = schema_version
    else:
        normalized_schema_version = schema_version if type(schema_version) is int else None
        findings.append(
            _finding(
                "schema_violation",
                "severe",
                f"schema_version must be {MANIFEST_SCHEMA_VERSION}",
                str(path),
            )
        )

    source_name = manifest.get("source_name")
    if isinstance(source_name, str) and source_name.strip():
        claims["source_name"] = source_name
    else:
        findings.append(
            _finding("schema_violation", "severe", "source_name must be a non-empty string", str(path))
        )

    raw_sha256 = manifest.get("raw_sha256")
    if isinstance(raw_sha256, str) and _MANIFEST_SHA256_RE.fullmatch(raw_sha256):
        claims["raw_sha256"] = raw_sha256
    else:
        findings.append(
            _finding(
                "schema_violation",
                "severe",
                "raw_sha256 must be a 64-character lowercase hex string",
                str(path),
            )
        )

    if "raw_size_bytes" in manifest:
        raw_size_bytes = manifest.get("raw_size_bytes")
        if type(raw_size_bytes) is int and raw_size_bytes > 0:
            claims["raw_size_bytes"] = raw_size_bytes
        else:
            findings.append(
                _finding(
                    "schema_violation",
                    "severe",
                    "raw_size_bytes must be a positive integer",
                    str(path),
                )
            )

    if "source_kind" in manifest:
        source_kind = manifest.get("source_kind")
        if isinstance(source_kind, str) and source_kind in _MANIFEST_SOURCE_KINDS:
            claims["source_kind"] = source_kind
        else:
            findings.append(
                _finding(
                    "schema_violation",
                    "severe",
                    "source_kind must be 'file' or 'directory'",
                    str(path),
                )
            )

    return ParsedManifest(
        path=str(path),
        schema_version=normalized_schema_version,
        claims=claims,
        validated=not findings,
        findings=tuple(findings),
    )


def _manifest_payload_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        rel_path = path.relative_to(root)
        if _is_supported_manifest(rel_path):
            continue
        digest.update(str(rel_path).encode("utf-8"))
        digest.update(sha256_file(path).encode("ascii"))
    return digest.hexdigest()


def _materialize_redacted_tree(
    normalized_root: Path,
    redacted_root: Path,
    redacted_files: dict[Path, bytes],
) -> Path:
    reset_directory(redacted_root)
    for rel_path, data in sorted(redacted_files.items()):
        target = redacted_root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return redacted_root


def _manifest_mismatch(
    claims: dict,
    payload_sha256: str,
    raw_size_bytes: int,
    source_name: str,
    source_kind: str,
    path: str,
) -> list[dict]:
    findings = []
    claimed_hash = claims.get("raw_sha256")
    if claimed_hash == payload_sha256:
        pass
    elif claimed_hash:
        findings.append(
            _finding("provenance_gap", "severe", "manifest raw_sha256 does not match quarantined payload", path)
        )
    claimed_name = claims.get("source_name")
    if claimed_name == source_name:
        pass
    elif claimed_name:
        findings.append(
            _finding("provenance_gap", "severe", "manifest source_name does not match input name", path)
        )
    claimed_size = claims.get("raw_size_bytes")
    if claimed_size == raw_size_bytes:
        pass
    elif claimed_size is not None:
        findings.append(
            _finding("provenance_gap", "severe", "manifest raw_size_bytes does not match quarantined input", path)
        )
    claimed_kind = claims.get("source_kind")
    if claimed_kind == source_kind:
        pass
    elif claimed_kind is not None:
        findings.append(
            _finding("provenance_gap", "severe", "manifest source_kind does not match input kind", path)
        )
    return findings


def _compile_suspicious_pattern(pattern: str, context: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern, _SUSPICIOUS_TEXT_FLAGS)
    except re.error as error:
        raise ValueError(f"{context}: invalid regex: {error}") from error


def _compile_suspicious_rule(raw_rule: dict, context: str) -> SuspiciousTextRule:
    rule_id = raw_rule.get("id")
    pattern = raw_rule.get("pattern")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError(f"{context}: rule id must be a non-empty string")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError(f"{context}: rule pattern must be a non-empty string")
    description = raw_rule.get("description")
    if description is not None and not isinstance(description, str):
        raise ValueError(f"{context}: description must be a string")
    exclude_pattern_text = raw_rule.get("exclude_pattern")
    if exclude_pattern_text is not None and not isinstance(exclude_pattern_text, str):
        raise ValueError(f"{context}: exclude_pattern must be a string")
    window_lines = raw_rule.get("window_lines")
    if window_lines is not None and (not isinstance(window_lines, int) or window_lines < 0):
        raise ValueError(f"{context}: window_lines must be a non-negative integer")
    return SuspiciousTextRule(
        rule_id=rule_id,
        pattern=_compile_suspicious_pattern(pattern, context),
        description=description,
        exclude_pattern=(
            _compile_suspicious_pattern(exclude_pattern_text, context)
            if exclude_pattern_text is not None
            else None
        ),
        window_lines=window_lines,
    )


def _resolve_rule_pack_path(pack_path: str, policy: Policy) -> Path:
    candidate = Path(pack_path).expanduser()
    if candidate.is_absolute():
        return candidate
    if policy.source_path:
        return Path(policy.source_path).parent / candidate
    return Path.cwd() / candidate


def _load_rule_pack(pack_path: Path) -> tuple[SuspiciousTextPack, list[SuspiciousTextRule]]:
    try:
        raw_bytes = pack_path.read_bytes()
    except OSError as error:
        raise ValueError(f"unable to read suspicious-text rule pack {pack_path}: {error.strerror}") from error
    try:
        raw = tomllib.loads(raw_bytes.decode("utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"invalid suspicious-text rule pack {pack_path}: {error}") from error
    except UnicodeDecodeError as error:
        raise ValueError(f"invalid suspicious-text rule pack {pack_path}: {error}") from error

    if raw.get("schema_version") != 1:
        raise ValueError(f"invalid suspicious-text rule pack {pack_path}: schema_version must be 1")
    rules = raw.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError(f"invalid suspicious-text rule pack {pack_path}: rules must be a non-empty list")
    compiled = []
    for index, raw_rule in enumerate(rules, start=1):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"invalid suspicious-text rule pack {pack_path}: rule {index} must be a table")
        compiled_rule = _compile_suspicious_rule(raw_rule, f"{pack_path} rule {index}")
        compiled.append(
            SuspiciousTextRule(
                rule_id=compiled_rule.rule_id,
                pattern=compiled_rule.pattern,
                description=compiled_rule.description,
                exclude_pattern=compiled_rule.exclude_pattern,
                window_lines=compiled_rule.window_lines,
                source="pack",
                pack_path=str(pack_path.resolve()),
                pack_sha256=sha256_bytes(raw_bytes),
            )
        )
    pack = SuspiciousTextPack(
        path=str(pack_path.resolve()),
        sha256=sha256_bytes(raw_bytes),
        rule_count=len(compiled),
    )
    return pack, compiled


def load_suspicious_text_rules(policy: Policy) -> SuspiciousTextRuleSet:
    builtin_rules = [
        SuspiciousTextRule(
            rule_id=compiled.rule_id,
            pattern=compiled.pattern,
            description=compiled.description,
            exclude_pattern=compiled.exclude_pattern,
            window_lines=compiled.window_lines,
            source="builtin",
        )
        for compiled in (
            _compile_suspicious_rule(raw_rule, f"builtin rule {raw_rule['id']}")
            for raw_rule in _BUILTIN_RULE_DEFS
        )
    ]
    loaded_packs: list[SuspiciousTextPack] = []
    pack_rules: list[SuspiciousTextRule] = []
    for pack in policy.suspicious_text_rule_packs:
        if not isinstance(pack, str) or not pack:
            raise ValueError("suspicious_text_rule_packs entries must be non-empty strings")
        pack_info, compiled_rules = _load_rule_pack(_resolve_rule_pack_path(pack, policy))
        loaded_packs.append(pack_info)
        pack_rules.extend(compiled_rules)
    active_rules: list[SuspiciousTextRule] = []
    if policy.suspicious_text_enabled:
        active_rules.extend(builtin_rules)
        active_rules.extend(pack_rules)
    return SuspiciousTextRuleSet(
        enabled=policy.suspicious_text_enabled,
        normalization_version=SUSPICIOUS_TEXT_NORMALIZATION_VERSION,
        builtin_rule_count=len(builtin_rules) if policy.suspicious_text_enabled else 0,
        loaded_packs=tuple(loaded_packs),
        rules=tuple(active_rules),
    )


def suspicious_text_summary(rule_set: SuspiciousTextRuleSet) -> dict:
    return {
        "enabled": rule_set.enabled,
        "normalization_version": rule_set.normalization_version,
        "builtin_rule_count": rule_set.builtin_rule_count,
        "loaded_packs": [
            {
                "path": pack.path,
                "sha256": pack.sha256,
                "rule_count": pack.rule_count,
            }
            for pack in rule_set.loaded_packs
        ],
        "rule_count": rule_set.rule_count,
    }


def suspicious_text_rule_listing(rule_set: SuspiciousTextRuleSet, policy: Policy) -> list[dict]:
    rules = []
    for rule in rule_set.rules:
        effective_window = (
            rule.window_lines if rule.window_lines is not None else policy.suspicious_text_window_lines
        )
        entry = {
            "rule_id": rule.rule_id,
            "source": rule.source,
            "window_lines": max(0, effective_window),
        }
        if rule.description is not None:
            entry["description"] = rule.description
        if rule.pack_path is not None:
            entry["pack_path"] = rule.pack_path
        if rule.pack_sha256 is not None:
            entry["pack_sha256"] = rule.pack_sha256
        rules.append(entry)
    return rules


def _suspicious_text_snippet(text: str, match: re.Match[str], snippet_chars: int) -> str:
    start = max(0, match.start() - (snippet_chars // 2))
    end = min(len(text), start + snippet_chars)
    return safe_display(text[start:end])


def _fallback_suspicious_text_snippet(text: str, snippet_chars: int) -> str:
    return safe_display(text[:snippet_chars])


def _normalize_suspicious_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    folded = []
    for char in normalized:
        category = unicodedata.category(char)
        if category.startswith("C"):
            continue
        if category.startswith("P") or category.startswith("Z") or char.isspace():
            folded.append(" ")
            continue
        folded.append(char)
    return " ".join("".join(folded).split())


def _active_window_lines(rule: SuspiciousTextRule, policy: Policy) -> int:
    window_lines = rule.window_lines if rule.window_lines is not None else policy.suspicious_text_window_lines
    return max(0, window_lines)


def _scan_suspicious_text(
    decoded: str,
    rel_path: Path,
    policy: Policy,
    rule_set: SuspiciousTextRuleSet,
    include_suppressed_matches: bool = False,
) -> SuspiciousTextScanResult:
    if not policy.suspicious_text_enabled or not rule_set.rules:
        return SuspiciousTextScanResult(findings=(), suppressed_matches=())
    snippet_chars = max(16, policy.suspicious_text_snippet_chars)
    findings: list[dict] = []
    suppressed_matches: list[dict] = []
    seen: set[tuple[str, int, int, str]] = set()
    suppressed_seen: set[tuple[str, int, int, str, str]] = set()
    lines = decoded[: policy.suspicious_text_max_bytes].splitlines()

    for start_index in range(len(lines)):
        if len(findings) >= policy.suspicious_text_max_findings_per_file:
            break
        for rule in rule_set.rules:
            max_window_lines = _active_window_lines(rule, policy)
            matched_rule = False
            for span in range(1, max_window_lines + 2):
                end_index = start_index + span
                if end_index > len(lines):
                    break
                raw_text = "\n".join(lines[start_index:end_index])
                normalized_text = _normalize_suspicious_text(raw_text)
                start_line = start_index + 1
                end_line = end_index
                suppressed_match: dict | None = None
                for match_mode, candidate_text in (("raw", raw_text), ("normalized", normalized_text)):
                    match = rule.pattern.search(candidate_text)
                    if match is None:
                        continue
                    if rule.exclude_pattern is not None and rule.exclude_pattern.search(candidate_text):
                        if suppressed_match is None:
                            suppressed_match = {
                                "rule_id": rule.rule_id,
                                "line": start_line,
                                "reason": "exclude_pattern",
                                "match_mode": match_mode,
                            }
                            if end_line > start_line:
                                suppressed_match["end_line"] = end_line
                            if rule.source == "pack" and rule.pack_path is not None:
                                suppressed_match["pack_path"] = rule.pack_path
                        continue
                    snippet = (
                        _suspicious_text_snippet(raw_text, match, snippet_chars)
                        if match_mode == "raw"
                        else _fallback_suspicious_text_snippet(raw_text, snippet_chars)
                    )
                    key = (rule.rule_id, start_line, end_line, snippet)
                    if key in seen:
                        matched_rule = True
                        break
                    seen.add(key)
                    extra: dict[str, str | int] = {
                        "rule_id": rule.rule_id,
                        "line": start_line,
                        "snippet": snippet,
                        "match_mode": match_mode,
                    }
                    if end_line > start_line:
                        extra["end_line"] = end_line
                    findings.append(
                        _finding(
                            "suspicious_text",
                            "moderate",
                            f"suspicious text matched rule {rule.rule_id}",
                            str(rel_path),
                            **extra,
                        )
                    )
                    matched_rule = True
                    break
                if matched_rule:
                    break
                if suppressed_match is not None:
                    if include_suppressed_matches:
                        suppression_key = (
                            rule.rule_id,
                            start_line,
                            end_line,
                            suppressed_match["reason"],
                        )
                        if suppression_key not in suppressed_seen:
                            suppressed_seen.add(suppression_key)
                            suppressed_matches.append(suppressed_match)
                    matched_rule = True
                    break
            if matched_rule and len(findings) >= policy.suspicious_text_max_findings_per_file:
                break
    return SuspiciousTextScanResult(
        findings=tuple(findings),
        suppressed_matches=tuple(suppressed_matches),
    )


def suspicious_text_check(
    path: str,
    policy: Policy,
    rule_set: SuspiciousTextRuleSet | None = None,
) -> dict:
    source = Path(path).expanduser().resolve()
    if not source.exists():
        raise ValueError(f"input does not exist: {source}")
    if source.is_dir():
        raise ValueError("suspicious-text-check only accepts a single file")

    from wilderness.intake import identify_input_type

    artifact_type = identify_input_type(source)
    if artifact_type in {"zip", "tar"}:
        raise ValueError("suspicious-text-check does not inspect archives")

    data = read_bytes(source)
    if is_likely_binary(data):
        raise ValueError("suspicious-text-check only accepts decoded text files")

    decoded = data.decode("utf-8", errors="replace")
    if rule_set is None:
        rule_set = load_suspicious_text_rules(policy)
    scan = _scan_suspicious_text(
        decoded,
        source.name,
        policy,
        rule_set,
        include_suppressed_matches=True,
    )
    return {
        "input": str(source),
        "policy": policy.snapshot(),
        "normalization": {
            "enabled": rule_set.enabled,
            "version": rule_set.normalization_version,
        },
        "packs": suspicious_text_summary(rule_set)["loaded_packs"],
        "rules": suspicious_text_rule_listing(rule_set, policy),
        "findings": list(scan.findings),
        "suppressed_matches": list(scan.suppressed_matches),
    }


def inspect_bundle(
    intake: IntakeRecord,
    unpacked: UnpackResult,
    policy: Policy,
    history_path: Path | None = None,
    redacted_root: Path | None = None,
    suspicious_text_rules: SuspiciousTextRuleSet | None = None,
) -> dict:
    if suspicious_text_rules is None:
        suspicious_text_rules = load_suspicious_text_rules(policy)
    findings = list(unpacked.findings)
    file_records = []
    manifest_paths = []
    parsed_manifests: list[ParsedManifest] = []
    manifest_findings = []
    redaction_applied = False
    redacted_files: dict[Path, bytes] = {}

    for path in sorted(candidate for candidate in unpacked.normalized_output_path.rglob("*") if candidate.is_file()):
        rel_path = path.relative_to(unpacked.normalized_output_path)
        data = read_bytes(path)
        binary = is_likely_binary(data)
        file_record = {
            "path": str(rel_path),
            "size_bytes": len(data),
            "normalized_sha256": sha256_file(path),
            "binary": binary,
        }
        if binary and rel_path.suffix.lower() in TEXT_EXTENSIONS | {""}:
            findings.append(
                _finding("binary_payload", "severe", "binary payload hidden behind a text-like file", str(rel_path))
            )
        if has_control_chars(data.decode("utf-8", errors="ignore")):
            snippet = safe_display(data.decode("utf-8", errors="replace")[:80])
            findings.append(
                _finding(
                    "control_sequence",
                    "moderate",
                    f"control characters found in file content: {snippet}",
                    str(rel_path),
                )
            )

        if not binary:
            decoded = data.decode("utf-8", errors="replace")
            max_line = max((len(line) for line in decoded.splitlines()), default=0)
            if max_line > policy.max_line_length:
                findings.append(
                    _finding("oversize", "severe", "line length exceeds policy limit", str(rel_path))
                )
            if rel_path.suffix.lower() == ".json":
                try:
                    json.loads(decoded)
                except json.JSONDecodeError as error:
                    findings.append(
                        _finding("schema_violation", "severe", f"json parse failed: {error}", str(rel_path))
                    )
                    findings.append(
                        _finding("format_confusion", "moderate", "file claims to be json but does not parse", str(rel_path))
                    )
            if rel_path.suffix.lower() == ".xml":
                try:
                    ET.fromstring(decoded)
                except ET.ParseError as error:
                    findings.append(
                        _finding("schema_violation", "severe", f"xml parse failed: {error}", str(rel_path))
                    )

            if rel_path.suffix.lower() in TEXT_EXTENSIONS | {""}:
                findings.extend(
                    _scan_suspicious_text(decoded, rel_path, policy, suspicious_text_rules).findings
                )

            if _is_supported_manifest(rel_path):
                manifest_paths.append(str(rel_path))
                manifest, parse_error = _parse_manifest(rel_path, data)
                if parse_error:
                    manifest_findings.append(parse_error)
                elif manifest is not None:
                    parsed_manifests.append(_parse_manifest_schema(rel_path, manifest))

        if policy.redaction.enabled:
            redacted, changed = redact_bytes(data, policy)
            redacted_files[rel_path] = redacted
            file_record["redacted"] = changed
            if changed:
                file_record["redacted_sha256"] = sha256_bytes(redacted)
                redaction_applied = True
        file_records.append(file_record)

    manifest_present = bool(manifest_paths)
    manifest_validated = False
    manifest_schema_version: int | None = None
    manifest_claims: dict[str, str | int] = {}

    if len(manifest_paths) > 1:
        manifest_findings.append(
            _finding(
                "schema_violation",
                "severe",
                "multiple supported manifests found",
                ", ".join(manifest_paths),
            )
        )
    elif len(parsed_manifests) == 1:
        parsed_manifest = parsed_manifests[0]
        manifest_schema_version = parsed_manifest.schema_version
        manifest_claims = parsed_manifest.claims
        manifest_validated = parsed_manifest.validated
        manifest_findings.extend(parsed_manifest.findings)
        if parsed_manifest.validated:
            findings.extend(
                _manifest_mismatch(
                    parsed_manifest.claims,
                    _manifest_payload_sha256(unpacked.normalized_output_path),
                    intake.provenance["raw_size_bytes"],
                    intake.source_path.name,
                    intake.provenance["input"]["source_kind"],
                    parsed_manifest.path,
                )
            )

    findings.extend(manifest_findings)

    fallback_applied = False
    fallback_reason = None

    if not manifest_present:
        findings.append(
            _finding("provenance_gap", "moderate", "no manifest or provenance file found")
        )

    blocking = [
        finding for finding in findings if finding["severity"] in policy.promotion_blocking_severities
    ]
    status = "discard" if blocking else "shelter"
    promotion_reasons = []
    if blocking:
        promotion_reasons.append("blocking findings present")
    if not manifest_present and policy.manifest_required_for_promotion:
        fallback_eligible = (
            policy.manifest_free_fallback_enabled
            and policy.manifest_free_fallback_scope == "single_file_text_or_json"
            and intake.artifact_type in {"file", "json_file"}
            and len(file_records) == 1
            and not any(finding["family"] == "nested_archive" for finding in findings)
            and not blocking
        )
        if fallback_eligible:
            fallback_applied = True
        else:
            if not policy.manifest_free_fallback_enabled:
                fallback_reason = "manifest required for promotion"
            else:
                fallback_reason = "manifest-free fallback not allowed for this artifact type"
            promotion_reasons.append(fallback_reason)
    if policy.redaction_required and not redaction_applied:
        promotion_reasons.append("redaction required by policy but no changes were applied")

    redaction_path = None
    redaction_digest = None
    if policy.redaction.enabled and redaction_applied and redacted_root is not None:
        redaction_path = _materialize_redacted_tree(
            unpacked.normalized_output_path,
            redacted_root,
            redacted_files,
        )
        redaction_digest = sha256_directory(redaction_path)

    artifact = {
        "artifact_type": intake.artifact_type,
        "schema_version": "1",
        "input_ref": {
            "source_path": str(intake.source_path),
            "quarantine_path": str(intake.quarantine_path),
        },
        "history_path": str(history_path.resolve()) if history_path is not None else None,
        "inspection_id": intake.inspection_id,
        "received_at": intake.provenance["received_at"],
        "suspicious_text": suspicious_text_summary(suspicious_text_rules),
        "manifest": {
            "present": manifest_present,
            "paths": manifest_paths,
            "required_for_promotion": policy.manifest_required_for_promotion,
            "fallback_applied": fallback_applied,
            "fallback_scope": policy.manifest_free_fallback_scope,
            "validated": manifest_validated,
            "schema_version": manifest_schema_version,
            "claims": manifest_claims,
        },
        "discard": {
            "retained": False,
            "path": None,
            "source": "raw_quarantine_copy",
        },
        "redaction": {
            "enabled": policy.redaction.enabled,
            "required": policy.redaction_required,
            "applied": redaction_applied,
            "available": redaction_path is not None,
            "path": str(redaction_path.resolve()) if redaction_path is not None else None,
            "normalized_sha256": redaction_digest,
        },
        "provenance": {
            **intake.provenance,
            "normalized_path": str(unpacked.normalized_output_path),
            "normalized_sha256": sha256_directory(unpacked.normalized_output_path),
            "manifest_paths": manifest_paths,
            "redaction_applied": redaction_applied,
        },
        "files": file_records,
        "findings": findings,
        "policy": policy.snapshot(),
        "status": status,
        "promotion": {
            "eligible": not promotion_reasons and status == "shelter",
            "blocking_reasons": promotion_reasons,
            "target_path": None,
        },
    }
    return artifact


def manifest_check(path: str) -> dict:
    source = Path(path).expanduser().resolve()
    manifests = []
    manifest_errors = []
    parsed_manifests: list[ParsedManifest] = []

    def parse_candidate(candidate: Path, data: bytes | None = None) -> None:
        payload = data if data is not None else candidate.read_bytes()
        manifest, error = _parse_manifest(candidate, payload)
        manifests.append(str(candidate))
        if error:
            manifest_errors.append(error)
            return
        if manifest is not None:
            parsed = _parse_manifest_schema(candidate, manifest)
            parsed_manifests.append(parsed)
            manifest_errors.extend(parsed.findings)

    if source.is_dir():
        for candidate in sorted(source.rglob("*")):
            if candidate.is_file() and _is_supported_manifest(candidate):
                parse_candidate(candidate)
    elif source.is_file() and _is_supported_manifest(source):
        parse_candidate(source)
    else:
        from wilderness.intake import identify_input_type
        import tarfile
        import zipfile

        artifact_type = identify_input_type(source)
        if artifact_type == "zip":
            with zipfile.ZipFile(source) as archive:
                for info in archive.infolist():
                    name = Path(info.filename).name.lower()
                    if name in SUPPORTED_MANIFEST_NAMES:
                        parse_candidate(Path(info.filename), archive.read(info))
        elif artifact_type == "tar":
            with tarfile.open(source, mode="r:*") as archive:
                for member in archive.getmembers():
                    if member.isdir():
                        continue
                    name = Path(member.name).name.lower()
                    if name not in SUPPORTED_MANIFEST_NAMES:
                        continue
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    parse_candidate(Path(member.name), handle.read())

    if len(manifests) > 1:
        manifest_errors.append(
            _finding(
                "schema_violation",
                "severe",
                "multiple supported manifests found",
                ", ".join(manifests),
            )
        )

    return {
        "input": str(source),
        "manifests": manifests,
        "valid": bool(manifests) and len(manifests) == 1 and not manifest_errors and len(parsed_manifests) == 1,
        "errors": manifest_errors,
    }
