from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from wilderness.inspect import inspect_bundle, load_suspicious_text_rules, manifest_check
from wilderness.intake import land_input
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
from wilderness.common import sha256_directory
from wilderness.unpack import build_shelter

EXIT_OK = 0
EXIT_REVIEW = 10
EXIT_BLOCKED = 20


def _report_path(state_root: Path, inspection_id: str) -> Path:
    return state_root / "reports" / f"{inspection_id}.json"


def _current_blocking_reasons(artifact: dict) -> list[str]:
    reasons = list(artifact["promotion"]["blocking_reasons"])
    if reasons:
        return reasons

    normalized_path = Path(artifact["provenance"]["normalized_path"])
    if not normalized_path.exists():
        return ["normalized shelter output is missing"]

    current_digest = sha256_directory(normalized_path)
    if current_digest != artifact["provenance"]["normalized_sha256"]:
        return ["inspection artifact is stale or shelter contents changed"]
    return []


def _promoted_target_path(artifact: dict) -> str | None:
    for event in reversed(load_history_for_report(artifact)):
        if event["event_type"] == "promoted":
            return event["payload"].get("target_path")
    return None


def _is_currently_promoted(artifact: dict) -> bool:
    target_path = _promoted_target_path(artifact)
    return target_path is not None and Path(target_path).exists()


def _inspect_exit_code(artifact: dict) -> int:
    if artifact["status"] == "discard":
        return EXIT_BLOCKED
    if artifact["promotion"]["eligible"]:
        return EXIT_OK
    return EXIT_REVIEW


def cmd_inspect(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    try:
        suspicious_text_rules = load_suspicious_text_rules(policy)
    except ValueError as error:
        print(f"policy error: {error}", file=sys.stderr)
        return EXIT_BLOCKED
    intake, state = land_input(args.input, policy)
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
    unpacked = build_shelter(intake, state, policy, args.out)
    artifact = inspect_bundle(
        intake,
        unpacked,
        policy,
        history_path=history_path,
        suspicious_text_rules=suspicious_text_rules,
    )
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
    if args.json:
        print(report_path.read_text(encoding="utf-8"), end="")
    else:
        print(render_report(artifact))
        print(f"report_path: {report_path}")
    return _inspect_exit_code(artifact)


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

    normalized_path = Path(artifact["provenance"]["normalized_path"])
    target = Path(policy.state_root) / "safe-camp" / artifact["inspection_id"]
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(normalized_path, target)
    append_history_event(
        history_path,
        build_history_event(
            artifact["inspection_id"],
            "promoted",
            {"target_path": str(target.resolve())},
        ),
    )
    print(f"promoted_to: {target}")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    artifact = load_report(args.report)
    promoted = _is_currently_promoted(artifact)
    promotable = artifact["promotion"]["eligible"] and not _current_blocking_reasons(artifact)

    if args.require_promoted:
        if promoted:
            print("verified: promoted")
            return EXIT_OK
        print("verification failed: artifact is not in safe camp")
        return EXIT_BLOCKED

    if promoted:
        print("verified: promoted")
        return EXIT_OK
    if promotable:
        print("verified: promotable")
        return EXIT_OK

    print("verification failed: " + ", ".join(_current_blocking_reasons(artifact)))
    return EXIT_BLOCKED


def cmd_manifest_check(args: argparse.Namespace) -> int:
    result = manifest_check(args.input)
    print(f"input: {result['input']}")
    print(f"valid: {result['valid']}")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wilderness")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("input")
    inspect_parser.add_argument("--out")
    inspect_parser.add_argument("--json", action="store_true")
    inspect_parser.add_argument("--policy")
    inspect_parser.set_defaults(func=cmd_inspect)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("report")
    report_parser.set_defaults(func=cmd_report)

    promote_parser = subparsers.add_parser("promote")
    promote_parser.add_argument("report")
    promote_parser.add_argument("--policy")
    promote_parser.set_defaults(func=cmd_promote)

    manifest_parser = subparsers.add_parser("manifest-check")
    manifest_parser.add_argument("input")
    manifest_parser.add_argument("--policy")
    manifest_parser.set_defaults(func=cmd_manifest_check)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("report")
    verify_parser.add_argument("--require-promoted", action="store_true")
    verify_parser.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
