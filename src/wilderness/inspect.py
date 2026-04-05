from __future__ import annotations

import json
from pathlib import Path
import tomllib
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


def _finding(family: str, severity: str, message: str, path: str | None = None) -> dict:
    finding = {"family": family, "severity": severity, "message": message}
    if path is not None:
        finding["path"] = path
    return finding


def _parse_manifest(path: Path, data: bytes) -> tuple[dict | None, dict | None]:
    lower_name = path.name.lower()
    try:
        if lower_name.endswith(".json"):
            return json.loads(data.decode("utf-8")), None
        if lower_name.endswith(".toml"):
            return tomllib.loads(data.decode("utf-8")), None
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        return None, _finding("schema_violation", "severe", f"manifest parse failed: {error}", str(path))
    return None, None


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


def inspect_bundle(intake: IntakeRecord, unpacked: UnpackResult, policy: Policy) -> dict:
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

            lower_name = rel_path.name.lower()
            if lower_name.startswith("manifest") or lower_name == "provenance.json":
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
    if policy.redaction_required and not redaction_applied:
        promotion_reasons.append("redaction required by policy but no changes were applied")

    artifact = {
        "artifact_type": intake.artifact_type,
        "schema_version": "1",
        "input_ref": {
            "source_path": str(intake.source_path),
            "quarantine_path": str(intake.quarantine_path),
        },
        "inspection_id": intake.inspection_id,
        "received_at": intake.provenance["received_at"],
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
        elif manifest is None:
            parse_errors.append(
                _finding("schema_violation", "moderate", "manifest format unsupported", str(candidate))
            )

    if source.is_dir():
        for candidate in source.rglob("manifest.*"):
            parse_candidate(candidate)
    elif source.suffix.lower() in {".json", ".toml"} and source.name.lower().startswith("manifest"):
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
                    if name.startswith("manifest."):
                        parse_candidate(Path(info.filename), archive.read(info))
        elif artifact_type == "tar":
            with tarfile.open(source, mode="r:*") as archive:
                for member in archive.getmembers():
                    if member.isdir():
                        continue
                    name = Path(member.name).name.lower()
                    if not name.startswith("manifest."):
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
