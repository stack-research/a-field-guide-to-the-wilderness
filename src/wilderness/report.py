from __future__ import annotations

import json
from pathlib import Path

from wilderness.common import dump_json, safe_display


def write_report(report: dict, path: Path) -> Path:
    dump_json(report, path)
    return path


def load_report(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


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
    for finding in report["findings"][:10]:
        path = finding.get("path", "-")
        if finding["family"] == "suspicious_text":
            line = finding.get("line", "?")
            rule_id = finding.get("rule_id", "unknown")
            snippet = finding.get("snippet", "")
            lines.append(
                f"[{finding['severity']}] suspicious_text {safe_display(path)}:{line} {safe_display(rule_id)} :: {safe_display(snippet)}"
            )
            continue
        lines.append(
            f"[{finding['severity']}] {finding['family']} {safe_display(path)} :: {safe_display(finding['message'])}"
        )
    return "\n".join(lines)
