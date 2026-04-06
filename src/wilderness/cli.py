from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from wilderness.inspect import (
    inspect_bundle,
    load_suspicious_text_rules,
    manifest_check,
    suspicious_text_check,
    suspicious_text_rule_listing,
)
from wilderness.intake import land_input, retain_discard_copy
from wilderness.policy import load_policy
from wilderness.provenance import build_history_event, inspection_history_path
from wilderness.report import (
    append_history_event,
    apply_history,
    load_history_for_report,
    load_report,
    render_report,
    write_report,
)
from wilderness.common import safe_display, sha256_directory, sha256_file
from wilderness.unpack import build_shelter

EXIT_OK = 0
EXIT_REVIEW = 10
EXIT_BLOCKED = 20


def _report_path(state_root: Path, inspection_id: str) -> Path:
    return state_root / "reports" / f"{inspection_id}.json"


def _result_class(exit_code: int) -> str:
    if exit_code == EXIT_OK:
        return "promotable"
    if exit_code == EXIT_REVIEW:
        return "review_needed"
    return "blocked"


def _source_resolution(
    *,
    available: bool,
    resolved_from: str | None,
    origin: str | None,
    path: Path | None,
    sha256: str | None,
    error: str | None,
) -> dict:
    return {
        "available": available,
        "resolved_from": resolved_from,
        "origin": origin,
        "path": str(path.resolve()) if path is not None else None,
        "sha256": sha256,
        "error": error,
    }


def _resolve_report_source(artifact: dict) -> dict:
    effective_source = artifact.get("effective_source")
    if effective_source:
        path = effective_source.get("path")
        if path is None:
            return _source_resolution(
                available=False,
                resolved_from=effective_source.get("resolved_from"),
                origin="report_state",
                path=None,
                sha256=effective_source.get("sha256"),
                error="effective source is unavailable",
            )
        return _source_resolution(
            available=True,
            resolved_from=effective_source.get("resolved_from"),
            origin="report_state",
            path=Path(path),
            sha256=effective_source.get("sha256"),
            error=None,
        )

    redaction = artifact.get("redaction", {})
    if redaction.get("required"):
        path = redaction.get("path")
        if not redaction.get("available") or not path:
            return _source_resolution(
                available=False,
                resolved_from="redacted",
                origin="report_state",
                path=None,
                sha256=None,
                error="required redacted derivative is missing",
            )
        return _source_resolution(
            available=True,
            resolved_from="redacted",
            origin="report_state",
            path=Path(path),
            sha256=redaction.get("normalized_sha256"),
            error=None,
        )

    provenance = artifact["provenance"]
    normalized_path = provenance.get("normalized_path")
    if normalized_path is None:
        return _source_resolution(
            available=False,
            resolved_from="shelter",
            origin="report_state",
            path=None,
            sha256=None,
            error="normalized shelter output is unavailable",
        )
    return _source_resolution(
        available=True,
        resolved_from="shelter",
        origin="report_state",
        path=Path(normalized_path),
        sha256=provenance.get("normalized_sha256"),
        error=None,
    )


def _effective_file_hashes(artifact: dict) -> dict[str, str]:
    effective_source = artifact.get("effective_source", {})
    effective_from = effective_source.get("resolved_from")
    files: dict[str, str] = {}
    for file_record in artifact.get("files", []):
        expected_sha256 = file_record.get("effective_sha256")
        if expected_sha256 is None:
            if effective_from == "redacted" and "redacted_sha256" in file_record:
                expected_sha256 = file_record["redacted_sha256"]
            else:
                expected_sha256 = file_record.get("normalized_sha256")
        if expected_sha256 is not None:
            files[file_record["path"]] = expected_sha256
    return files


def _directory_file_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file())
    }


def _latest_promoted_event(artifact: dict) -> dict | None:
    return next(
        (event for event in reversed(load_history_for_report(artifact)) if event["event_type"] == "promoted"),
        None,
    )


def _promoted_target_exists(artifact: dict) -> bool:
    target_path = _promoted_target_path(artifact)
    return target_path is not None and Path(target_path).exists()


def _promoted_source_error(artifact: dict) -> str | None:
    promoted_event = _latest_promoted_event(artifact)
    if promoted_event is None:
        return "promoted safe-camp copy is missing"
    target_path = promoted_event["payload"].get("target_path")
    if not target_path:
        return "promoted safe-camp copy is missing"
    promoted_root = Path(target_path)
    if not promoted_root.exists():
        return "promoted safe-camp copy is missing"

    expected_files = _effective_file_hashes(artifact)
    current_files = _directory_file_hashes(promoted_root)

    missing_paths = sorted(set(expected_files) - set(current_files))
    if missing_paths:
        return f"promoted safe-camp copy is stale: missing file {safe_display(missing_paths[0])}"

    extra_paths = sorted(set(current_files) - set(expected_files))
    if extra_paths:
        return f"promoted safe-camp copy is stale: unexpected file {safe_display(extra_paths[0])}"

    changed_paths = [
        relative_path
        for relative_path in sorted(expected_files)
        if current_files[relative_path] != expected_files[relative_path]
    ]
    if changed_paths:
        return f"promoted safe-camp copy is stale: content changed for {safe_display(changed_paths[0])}"

    expected_digest = (
        promoted_event["payload"].get("target_sha256")
        or promoted_event["payload"].get("source_sha256")
        or artifact.get("effective_source", {}).get("sha256")
    )
    if expected_digest is None:
        return "promoted safe-camp attestation is incomplete"

    current_digest = sha256_directory(promoted_root)
    if current_digest != expected_digest:
        return "promoted safe-camp copy is stale or contents changed"

    expected_file_count = (
        promoted_event["payload"].get("file_count")
        or artifact.get("effective_source", {}).get("file_count")
    )
    if expected_file_count is not None and len(current_files) != expected_file_count:
        return "promoted safe-camp copy is stale or contents changed"
    return None


def _resolve_source(artifact: dict, mode: str = "auto") -> dict:
    if mode == "auto":
        promoted = _resolve_source(artifact, "promoted")
        if promoted["available"]:
            return promoted
        if _promoted_target_exists(artifact):
            return promoted
        return _resolve_source(artifact, "effective")
    if mode == "effective":
        return _resolve_report_source(artifact)
    if mode == "promoted":
        promoted_event = _latest_promoted_event(artifact)
        target_path = promoted_event["payload"].get("target_path") if promoted_event is not None else None
        if target_path is None:
            return _source_resolution(
                available=False,
                resolved_from="promoted",
                origin="live_safe_camp",
                path=None,
                sha256=None,
                error="promoted safe-camp copy is missing",
            )
        path = Path(target_path)
        promoted_error = _promoted_source_error(artifact)
        if promoted_error is not None:
            return _source_resolution(
                available=False,
                resolved_from="promoted",
                origin="live_safe_camp",
                path=path,
                sha256=None,
                error=promoted_error,
            )
        return _source_resolution(
            available=True,
            resolved_from="promoted",
            origin="live_safe_camp",
            path=path,
            sha256=sha256_directory(path),
            error=None,
        )
    if mode == "redacted":
        redaction = artifact.get("redaction", {})
        path = redaction.get("path")
        if not redaction.get("available") or not path:
            return _source_resolution(
                available=False,
                resolved_from="redacted",
                origin="report_state",
                path=None,
                sha256=None,
                error="redacted derivative is missing",
            )
        return _source_resolution(
            available=True,
            resolved_from="redacted",
            origin="report_state",
            path=Path(path),
            sha256=redaction.get("normalized_sha256"),
            error=None,
        )
    if mode == "shelter":
        provenance = artifact["provenance"]
        normalized_path = provenance.get("normalized_path")
        if normalized_path is None:
            return _source_resolution(
                available=False,
                resolved_from="shelter",
                origin="report_state",
                path=None,
                sha256=None,
                error="normalized shelter output is unavailable",
            )
        return _source_resolution(
            available=True,
            resolved_from="shelter",
            origin="report_state",
            path=Path(normalized_path),
            sha256=provenance.get("normalized_sha256"),
            error=None,
        )
    raise ValueError(f"unsupported source mode: {mode}")


def _current_source_error(resolution: dict) -> str | None:
    if not resolution["available"]:
        return resolution["error"] or "effective source is unavailable"
    path_value = resolution.get("path")
    sha256 = resolution.get("sha256")
    if path_value is None:
        return resolution["error"] or "effective source is unavailable"
    path = Path(path_value)
    if resolution["resolved_from"] == "promoted":
        if not path.exists():
            return "promoted safe-camp copy is missing"
        return None
    if sha256 is None:
        return "effective source digest is unavailable"
    if not path.exists():
        if resolution["resolved_from"] == "redacted":
            return "required redacted derivative is missing"
        return "normalized shelter output is missing"
    current_digest = sha256_directory(path)
    if current_digest != sha256:
        if resolution["resolved_from"] == "redacted":
            return "inspection artifact is stale or redacted contents changed"
        return "inspection artifact is stale or shelter contents changed"
    return None


def _replace_tree(source: Path, target: Path) -> None:
    if source.resolve() == target.resolve():
        raise ValueError("export destination cannot be the same as the resolved source")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    shutil.copytree(source, target)


def _current_blocking_reasons(artifact: dict) -> list[str]:
    reasons = list(artifact["promotion"]["blocking_reasons"])
    if reasons:
        return reasons

    source_error = _current_source_error(_resolve_source(artifact, "effective"))
    if source_error is not None:
        return [source_error]
    return []


def _promoted_target_path(artifact: dict) -> str | None:
    promoted_event = _latest_promoted_event(artifact)
    if promoted_event is None:
        return None
    return promoted_event["payload"].get("target_path")


def _is_currently_promoted(artifact: dict) -> bool:
    return _resolve_source(artifact, "promoted")["available"]


def _inspect_exit_code(artifact: dict) -> int:
    if artifact["status"] == "discard":
        return EXIT_BLOCKED
    if artifact["promotion"]["eligible"]:
        return EXIT_OK
    return EXIT_REVIEW


def _load_policy_and_rules(policy_path: str | None):
    policy = load_policy(policy_path)
    policy_error = _validate_policy(policy)
    if policy_error is not None:
        print(f"policy error: {policy_error}", file=sys.stderr)
        return None, None
    suspicious_text_rules = _load_rule_set_or_error(policy)
    if suspicious_text_rules is None:
        return None, None
    return policy, suspicious_text_rules


def _run_inspection(
    input_path: str,
    *,
    policy,
    suspicious_text_rules,
    out_path: str | None = None,
) -> tuple[dict, Path]:
    intake, state = land_input(input_path, policy)
    history_path = inspection_history_path(state.root, intake.inspection_id)
    append_history_event(
        history_path,
        build_history_event(
            intake.inspection_id,
            "received",
            {
                "artifact_type": intake.artifact_type,
                "source_path": str(intake.source_path),
                "quarantine_path": str(intake.quarantine_path),
                "raw_sha256": intake.provenance["raw_sha256"],
            },
        ),
    )
    unpacked = build_shelter(intake, state, policy, out_path)
    artifact = inspect_bundle(
        intake,
        unpacked,
        policy,
        history_path=history_path,
        redacted_root=state.redacted / intake.inspection_id,
        suspicious_text_rules=suspicious_text_rules,
    )
    discard_path = None
    if artifact["status"] == "discard" and policy.discard_retention_enabled:
        discard_path = retain_discard_copy(intake.quarantine_path, state, intake.inspection_id)
        artifact["discard"]["retained"] = True
        artifact["discard"]["path"] = str(discard_path.resolve())
    report_path = write_report(artifact, _report_path(state.root, intake.inspection_id))
    append_history_event(
        history_path,
        build_history_event(
            intake.inspection_id,
            "inspected",
            {
                "report_path": str(report_path.resolve()),
                "status": artifact["status"],
                "promotion_eligible": artifact["promotion"]["eligible"],
                "finding_count": len(artifact["findings"]),
            },
        ),
    )
    if discard_path is not None:
        append_history_event(
            history_path,
            build_history_event(
                intake.inspection_id,
                "discard_retained",
                {
                    "discard_path": str(discard_path.resolve()),
                    "source": artifact["discard"]["source"],
                },
            ),
        )
    return artifact, report_path


def _emit_inspect_output(artifact: dict, report_path: Path, *, as_json: bool) -> None:
    if as_json:
        print(report_path.read_text(encoding="utf-8"), end="")
        return
    print(render_report(artifact))
    print(f"report_path: {report_path}")


def _scan_result(
    input_path: str,
    *,
    exit_code: int,
    artifact: dict | None = None,
    report_path: Path | None = None,
    error: str | None = None,
) -> dict:
    return {
        "input": str(Path(input_path).expanduser().resolve()),
        "exit_code": exit_code,
        "status": artifact["status"] if artifact is not None else None,
        "inspection_id": artifact["inspection_id"] if artifact is not None else None,
        "report_path": str(report_path.resolve()) if report_path is not None else None,
        "error": error,
    }


def _scan_counts(results: list[dict]) -> dict[str, int]:
    return {
        "promotable": sum(1 for result in results if result["exit_code"] == EXIT_OK),
        "review_needed": sum(1 for result in results if result["exit_code"] == EXIT_REVIEW),
        "blocked": sum(1 for result in results if result["exit_code"] == EXIT_BLOCKED),
    }


def _scan_exit_code(results: list[dict]) -> int:
    if any(result["exit_code"] == EXIT_BLOCKED for result in results):
        return EXIT_BLOCKED
    if any(result["exit_code"] == EXIT_REVIEW for result in results):
        return EXIT_REVIEW
    return EXIT_OK


def _read_scan_input_list(path: str) -> list[str]:
    raw_lines = Path(path).expanduser().read_text(encoding="utf-8").splitlines()
    return [line for line in raw_lines if line.strip()]


def _render_scan_result(result: dict) -> str:
    parts = [
        safe_display(result["input"]),
        f"class={_result_class(result['exit_code'])}",
        f"status={result['status'] or '-'}",
    ]
    if result["inspection_id"] is not None:
        parts.append(f"inspection_id={result['inspection_id']}")
    if result["report_path"] is not None:
        parts.append(f"report_path={safe_display(result['report_path'])}")
    if result["error"] is not None:
        parts.append(f"error={safe_display(result['error'])}")
    return " ".join(parts)


def _load_rule_set_or_error(policy: object):
    try:
        return load_suspicious_text_rules(policy)
    except ValueError as error:
        print(f"policy error: {error}", file=sys.stderr)
        return None


def _validate_policy(policy) -> str | None:
    if not isinstance(policy.suspicious_text_block_rule_ids, list):
        return "suspicious_text_block_rule_ids must be a list"
    seen_rule_ids: set[str] = set()
    for rule_id in policy.suspicious_text_block_rule_ids:
        if not isinstance(rule_id, str) or not rule_id:
            return "suspicious_text_block_rule_ids entries must be non-empty strings"
        if rule_id in seen_rule_ids:
            return "suspicious_text_block_rule_ids entries must be unique"
        seen_rule_ids.add(rule_id)
    if policy.manifest_free_fallback_scope != "single_file_text_or_json":
        return "manifest_free_fallback_scope must be 'single_file_text_or_json'"
    if policy.manifest_free_fallback_enabled and not policy.manifest_required_for_promotion:
        return "manifest_free_fallback_enabled requires manifest_required_for_promotion to stay true"
    if policy.discard_copy_mode != "copy":
        return "discard_copy_mode must be 'copy'"
    return None


def cmd_inspect(args: argparse.Namespace) -> int:
    policy, suspicious_text_rules = _load_policy_and_rules(args.policy)
    if policy is None or suspicious_text_rules is None:
        return EXIT_BLOCKED
    artifact, report_path = _run_inspection(
        args.input,
        policy=policy,
        suspicious_text_rules=suspicious_text_rules,
        out_path=args.out,
    )
    _emit_inspect_output(artifact, report_path, as_json=args.json)
    return _inspect_exit_code(artifact)


def cmd_scan(args: argparse.Namespace) -> int:
    policy, suspicious_text_rules = _load_policy_and_rules(args.policy)
    if policy is None or suspicious_text_rules is None:
        return EXIT_BLOCKED

    inputs = list(args.inputs)
    if args.input_list:
        try:
            inputs.extend(_read_scan_input_list(args.input_list))
        except OSError as error:
            print(f"scan error: unable to read input list: {error}", file=sys.stderr)
            return EXIT_BLOCKED

    if not inputs:
        print("scan error: no inputs provided", file=sys.stderr)
        return EXIT_BLOCKED

    results = []
    for input_path in inputs:
        try:
            artifact, report_path = _run_inspection(
                input_path,
                policy=policy,
                suspicious_text_rules=suspicious_text_rules,
            )
        except OSError as error:
            results.append(
                _scan_result(
                    input_path,
                    exit_code=EXIT_BLOCKED,
                    error=str(error),
                )
            )
            continue
        results.append(
            _scan_result(
                input_path,
                exit_code=_inspect_exit_code(artifact),
                artifact=artifact,
                report_path=report_path,
            )
        )

    counts = _scan_counts(results)
    payload = {
        "total_inputs": len(results),
        "promotable": counts["promotable"],
        "review_needed": counts["review_needed"],
        "blocked": counts["blocked"],
        "results": results,
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for result in results:
            print(_render_scan_result(result))
        print(
            "totals: "
            f"total_inputs={payload['total_inputs']} "
            f"promotable={payload['promotable']} "
            f"review_needed={payload['review_needed']} "
            f"blocked={payload['blocked']}"
        )
    return _scan_exit_code(results)


def cmd_report(args: argparse.Namespace) -> int:
    artifact = load_report(args.report)
    print(render_report(apply_history(artifact, load_history_for_report(artifact))))
    return EXIT_OK


def cmd_promote(args: argparse.Namespace) -> int:
    artifact = load_report(args.report)
    policy = load_policy(args.policy)
    blockers = _current_blocking_reasons(artifact)
    history_path = Path(artifact["history_path"])
    if blockers:
        append_history_event(
            history_path,
            build_history_event(
                artifact["inspection_id"],
                "promotion_blocked",
                {"reasons": blockers},
            ),
        )
        print("promotion blocked: " + ", ".join(blockers))
        return EXIT_BLOCKED

    resolution = _resolve_source(artifact, "effective")
    source_error = _current_source_error(resolution)
    if source_error is not None or resolution["path"] is None:
        print("promotion blocked: " + (source_error or "effective promotion source is unavailable"))
        return EXIT_BLOCKED
    source_path = Path(resolution["path"])
    target = Path(policy.state_root) / "safe-camp" / artifact["inspection_id"]
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source_path, target)
    target_digest = sha256_directory(target)
    if target_digest != resolution["sha256"]:
        shutil.rmtree(target)
        reasons = ["promoted safe-camp copy did not match effective source"]
        append_history_event(
            history_path,
            build_history_event(
                artifact["inspection_id"],
                "promotion_blocked",
                {"reasons": reasons},
            ),
        )
        print("promotion blocked: " + ", ".join(reasons))
        return EXIT_BLOCKED
    append_history_event(
        history_path,
        build_history_event(
            artifact["inspection_id"],
            "promoted",
            {
                "target_path": str(target.resolve()),
                "resolved_from": resolution["resolved_from"],
                "source_path": resolution["path"],
                "source_sha256": resolution["sha256"],
                "target_sha256": target_digest,
                "file_count": artifact.get("effective_source", {}).get("file_count", len(artifact.get("files", []))),
            },
        ),
    )
    print(f"promoted_to: {target}")
    return EXIT_OK


def cmd_source(args: argparse.Namespace) -> int:
    artifact = load_report(args.report)
    resolution = _resolve_source(artifact, args.mode)
    source_error = _current_source_error(resolution)
    if source_error is not None:
        print(f"source unavailable: {source_error}")
        return EXIT_BLOCKED

    path_value = resolution["path"]
    if path_value is None:
        print("source unavailable: effective source is unavailable")
        return EXIT_BLOCKED

    source_path = Path(path_value)
    if args.out:
        destination = Path(args.out).expanduser().resolve()
        try:
            _replace_tree(source_path, destination)
        except ValueError as error:
            print(f"source unavailable: {error}")
            return EXIT_BLOCKED
    else:
        destination = None

    payload = {
        "inspection_id": artifact["inspection_id"],
        "resolved_source": "directory",
        "resolved_from": resolution["resolved_from"],
        "origin": resolution["origin"],
        "path": str(source_path.resolve()),
        "sha256": resolution["sha256"],
        "available": True,
    }
    if destination is not None:
        payload["exported_to"] = str(destination)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"inspection_id: {payload['inspection_id']}")
        print(f"resolved_source: {payload['resolved_source']}")
        print(f"resolved_from: {payload['resolved_from']}")
        print(f"origin: {payload['origin']}")
        print(f"path: {payload['path']}")
        print(f"sha256: {payload['sha256']}")
        print(f"available: {payload['available']}")
        if destination is not None:
            print(f"exported_to: {destination}")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    artifact = load_report(args.report)
    promoted_resolution = _resolve_source(artifact, "promoted")
    promoted = promoted_resolution["available"]
    promotable = artifact["promotion"]["eligible"] and not _current_blocking_reasons(artifact)

    if args.require_promoted:
        if promoted:
            print("verified: promoted")
            return EXIT_OK
        print("verification failed: " + (promoted_resolution["error"] or "artifact is not in safe camp"))
        return EXIT_BLOCKED

    if promoted:
        print("verified: promoted")
        return EXIT_OK
    if _promoted_target_exists(artifact):
        print("verification failed: " + (promoted_resolution["error"] or "artifact is not in safe camp"))
        return EXIT_BLOCKED
    if promotable:
        print("verified: promotable")
        return EXIT_OK

    print("verification failed: " + ", ".join(_current_blocking_reasons(artifact)))
    return EXIT_BLOCKED


def cmd_manifest_check(args: argparse.Namespace) -> int:
    result = manifest_check(args.input)
    print(f"input: {result['input']}")
    print(f"valid: {result['valid']}")
    print(f"promotable: {result['promotable']}")
    if result.get("promotion_note"):
        print(f"promotion_note: {result['promotion_note']}")
    if result["manifests"]:
        print("manifests:")
        for manifest in result["manifests"]:
            print(f"  - {manifest}")
    if result["errors"]:
        print("errors:")
        for error in result["errors"]:
            path = error.get("path", "-")
            print(f"  - [{error['severity']}] {path}: {error['message']}")
    return EXIT_OK if result["valid"] else EXIT_BLOCKED


def _render_suspicious_text_check(result: dict) -> str:
    lines = [
        f"input: {result['input']}",
        f"normalization_enabled: {result['normalization']['enabled']}",
        f"normalization_version: {result['normalization']['version']}",
        f"active_rules: {len(result['rules'])}",
    ]
    if result["packs"]:
        lines.append("loaded_packs:")
        for pack in result["packs"]:
            lines.append(
                f"  - {pack['path']} sha256={pack['sha256']} rules={pack['rule_count']}"
            )
    else:
        lines.append("loaded_packs: none")
    if result["findings"]:
        lines.append("findings:")
        for finding in result["findings"]:
            end_line = finding.get("end_line")
            line_display = (
                str(finding["line"])
                if end_line in (None, finding["line"])
                else f"{finding['line']}-{end_line}"
            )
            mode = f" {finding['match_mode']}" if finding.get("match_mode") == "normalized" else ""
            lines.append(
                f"  - {finding['rule_id']}{mode} line={line_display} :: {finding['snippet']}"
            )
    else:
        lines.append("findings: none")
    if result["suppressed_matches"]:
        lines.append("suppressed_matches:")
        for match in result["suppressed_matches"]:
            end_line = match.get("end_line")
            line_display = (
                str(match["line"])
                if end_line in (None, match["line"])
                else f"{match['line']}-{end_line}"
            )
            mode = f" {match['match_mode']}" if match.get("match_mode") else ""
            lines.append(
                f"  - {match['rule_id']}{mode} line={line_display} reason={match['reason']}"
            )
    else:
        lines.append("suppressed_matches: none")
    return "\n".join(lines)


def cmd_suspicious_text_check(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    rule_set = _load_rule_set_or_error(policy)
    if rule_set is None:
        return EXIT_BLOCKED
    if args.list_rules:
        payload = {
            "input": str(Path(args.input).expanduser().resolve()),
            "policy": policy.snapshot(),
            "normalization": {
                "enabled": rule_set.enabled,
                "version": rule_set.normalization_version,
            },
            "packs": [
                {"path": pack.path, "sha256": pack.sha256, "rule_count": pack.rule_count}
                for pack in rule_set.loaded_packs
            ],
            "rules": suspicious_text_rule_listing(rule_set, policy),
            "findings": [],
            "suppressed_matches": [],
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"input: {payload['input']}")
            print(f"normalization_enabled: {payload['normalization']['enabled']}")
            print(f"normalization_version: {payload['normalization']['version']}")
            print(f"active_rules: {len(payload['rules'])}")
            if payload["packs"]:
                print("loaded_packs:")
                for pack in payload["packs"]:
                    print(f"  - {pack['path']} sha256={pack['sha256']} rules={pack['rule_count']}")
            else:
                print("loaded_packs: none")
            print("rules:")
            for rule in payload["rules"]:
                pack_display = f" pack={rule['pack_path']}" if "pack_path" in rule else ""
                print(
                    f"  - {rule['rule_id']} source={rule['source']} window_lines={rule['window_lines']}{pack_display}"
                )
        return EXIT_OK
    try:
        result = suspicious_text_check(args.input, policy, rule_set=rule_set)
    except ValueError as error:
        print(f"suspicious-text-check error: {error}", file=sys.stderr)
        return EXIT_BLOCKED
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_render_suspicious_text_check(result))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wilderness")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("input")
    inspect_parser.add_argument("--out")
    inspect_parser.add_argument("--json", action="store_true")
    inspect_parser.add_argument("--policy")
    inspect_parser.set_defaults(func=cmd_inspect)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("inputs", nargs="*")
    scan_parser.add_argument("--input-list")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--policy")
    scan_parser.set_defaults(func=cmd_scan)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("report")
    report_parser.set_defaults(func=cmd_report)

    promote_parser = subparsers.add_parser("promote")
    promote_parser.add_argument("report")
    promote_parser.add_argument("--policy")
    promote_parser.set_defaults(func=cmd_promote)

    source_parser = subparsers.add_parser("source")
    source_parser.add_argument("report")
    source_parser.add_argument("--json", action="store_true")
    source_parser.add_argument("--out")
    source_parser.add_argument(
        "--mode",
        choices=("auto", "promoted", "redacted", "shelter"),
        default="auto",
    )
    source_parser.set_defaults(func=cmd_source)

    manifest_parser = subparsers.add_parser("manifest-check")
    manifest_parser.add_argument("input")
    manifest_parser.add_argument("--policy")
    manifest_parser.set_defaults(func=cmd_manifest_check)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("report")
    verify_parser.add_argument("--require-promoted", action="store_true")
    verify_parser.set_defaults(func=cmd_verify)

    suspicious_parser = subparsers.add_parser("suspicious-text-check")
    suspicious_parser.add_argument("input")
    suspicious_parser.add_argument("--policy")
    suspicious_parser.add_argument("--json", action="store_true")
    suspicious_parser.add_argument("--list-rules", action="store_true")
    suspicious_parser.set_defaults(func=cmd_suspicious_text_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
