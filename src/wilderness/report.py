from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from wilderness.common import dump_json, safe_display


def write_report(report: dict, path: Path) -> Path:
    dump_json(report, path)
    return path


def load_report(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def append_history_event(path: Path, event: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True))
        handle.write("\n")
    return path


def load_history(path: Path) -> list[dict]:
    if not path.exists():
        return []
    events = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def load_history_for_report(report: dict) -> list[dict]:
    history_path = report.get("history_path")
    if not history_path:
        return []
    return load_history(Path(history_path))


def apply_history(report: dict, events: list[dict]) -> dict:
    view = deepcopy(report)
    promoted_event = next(
        (event for event in reversed(events) if event["event_type"] == "promoted"),
        None,
    )
    if promoted_event is None:
        return view

    view["status"] = "safe_camp"
    view["promotion"]["eligible"] = True
    view["promotion"]["target_path"] = promoted_event["payload"].get("target_path")
    return view


def render_report(report: dict) -> str:
    counts: dict[str, int] = {}
    for finding in report["findings"]:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

    lines = [
        f"inspection_id: {report['inspection_id']}",
        f"status: {report['status']}",
        f"artifact_type: {report['artifact_type']}",
        f"files: {len(report['files'])}",
        f"promotion_eligible: {report['promotion']['eligible']}",
        "severity_counts: "
        + ", ".join(f"{severity}={count}" for severity, count in sorted(counts.items()))
        if counts
        else "severity_counts: none",
    ]
    if report["promotion"]["blocking_reasons"]:
        lines.append(
            "promotion_blockers: "
            + ", ".join(safe_display(reason) for reason in report["promotion"]["blocking_reasons"])
        )
    if report.get("manifest"):
        manifest = report["manifest"]
        blockers = report.get("promotion", {}).get("blocking_reasons", [])
        manifest_blocked = any("manifest" in reason for reason in blockers)
        manifest_invalid = manifest.get("present") and not manifest.get("validated", False)
        if manifest_blocked or manifest_invalid:
            lines.append(f"manifest_present: {manifest['present']}")
            if manifest.get("present"):
                lines.append(f"manifest_validated: {manifest.get('validated', False)}")
                if manifest.get("schema_version") is not None:
                    lines.append(f"manifest_schema_version: {manifest['schema_version']}")
    if report.get("redaction"):
        redaction = report["redaction"]
        if redaction.get("enabled") or redaction.get("required"):
            lines.append(f"redaction_applied: {redaction.get('applied', False)}")
            lines.append(f"redaction_available: {redaction.get('available', False)}")
            if redaction.get("path") is not None:
                lines.append(f"redaction_path: {safe_display(redaction['path'])}")
    if report.get("discard", {}).get("retained"):
        lines.append(f"discard_retained: {report['discard']['retained']}")
        lines.append(f"discard_path: {safe_display(report['discard']['path'])}")
    for finding in report["findings"][:10]:
        path = finding.get("path", "-")
        if finding["family"] == "suspicious_text":
            line = finding.get("line", "?")
            end_line = finding.get("end_line")
            rule_id = finding.get("rule_id", "unknown")
            match_mode = finding.get("match_mode")
            snippet = finding.get("snippet", "")
            line_display = str(line) if end_line in (None, line) else f"{line}-{end_line}"
            rule_display = safe_display(rule_id)
            if match_mode == "normalized":
                rule_display += " normalized"
            lines.append(
                f"[{finding['severity']}] suspicious_text {safe_display(path)}:{line_display} {rule_display} :: {safe_display(snippet)}"
            )
            continue
        lines.append(
            f"[{finding['severity']}] {finding['family']} {safe_display(path)} :: {safe_display(finding['message'])}"
        )
    return "\n".join(lines)
