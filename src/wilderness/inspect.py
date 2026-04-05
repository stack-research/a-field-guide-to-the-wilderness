from __future__ import annotations

from dataclasses import dataclass
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


def _manifest_mismatch(manifest: dict, raw_sha256: str, source_name: str, path: Path) -> list[dict]:
    findings = []
    claimed_hash = manifest.get("sha256") or manifest.get("raw_sha256") or manifest.get("source_sha256")
    if claimed_hash and claimed_hash != raw_sha256:
        findings.append(
            _finding("provenance_gap", "severe", "manifest hash does not match quarantined input", str(path))
        )
    claimed_name = manifest.get("source_name") or manifest.get("input_name")
    if claimed_name and claimed_name != source_name:
        findings.append(
            _finding("provenance_gap", "moderate", "manifest source name does not match input name", str(path))
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
    suspicious_text_rules: SuspiciousTextRuleSet | None = None,
) -> dict:
    if suspicious_text_rules is None:
        suspicious_text_rules = load_suspicious_text_rules(policy)
    findings = list(unpacked.findings)
    file_records = []
    manifest_paths = []
    manifest_errors = []
    redaction_applied = False

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
                    manifest_errors.append(parse_error)
                elif manifest is not None:
                    findings.extend(
                        _manifest_mismatch(
                            manifest,
                            intake.provenance["raw_sha256"],
                            intake.source_path.name,
                            rel_path,
                        )
                    )

            if policy.redaction.enabled:
                redacted, changed = redact_bytes(data, policy)
                if changed:
                    file_record["redacted_sha256"] = sha256_bytes(redacted)
                    redaction_applied = True
        file_records.append(file_record)

    findings.extend(manifest_errors)

    manifest_present = bool(manifest_paths)
    fallback_applied = False
    fallback_reason = None

    if not manifest_paths:
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
        },
        "discard": {
            "retained": False,
            "path": None,
            "source": "raw_quarantine_copy",
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
    parse_errors = []

    def parse_candidate(candidate: Path, data: bytes | None = None) -> None:
        payload = data if data is not None else candidate.read_bytes()
        manifest, error = _parse_manifest(candidate, payload)
        manifests.append(str(candidate))
        if error:
            parse_errors.append(error)

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

    return {
        "input": str(source),
        "manifests": manifests,
        "valid": not parse_errors and bool(manifests),
        "errors": parse_errors,
    }
