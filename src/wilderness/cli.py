from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from wilderness.inspect import inspect_bundle, manifest_check
from wilderness.intake import land_input
from wilderness.policy import load_policy
from wilderness.report import load_report, render_report, write_report
from wilderness.common import sha256_directory
from wilderness.unpack import build_shelter


def _report_path(state_root: Path, inspection_id: str) -> Path:
    return state_root / "reports" / f"{inspection_id}.json"


def cmd_inspect(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    intake, state = land_input(args.input, policy)
    unpacked = build_shelter(intake, state, policy, args.out)
    artifact = inspect_bundle(intake, unpacked, policy)
    report_path = write_report(artifact, _report_path(state.root, intake.inspection_id))
    if args.json:
        print(report_path.read_text(encoding="utf-8"), end="")
    else:
        print(render_report(artifact))
        print(f"report_path: {report_path}")
    return 0 if artifact["status"] != "discard" else 2


def cmd_report(args: argparse.Namespace) -> int:
    artifact = load_report(args.report)
    print(render_report(artifact))
    return 0


def cmd_promote(args: argparse.Namespace) -> int:
    artifact = load_report(args.report)
    policy = load_policy(args.policy)
    if not artifact["promotion"]["eligible"]:
        print("promotion blocked: " + ", ".join(artifact["promotion"]["blocking_reasons"]))
        return 2
    normalized_path = Path(artifact["provenance"]["normalized_path"])
    if not normalized_path.exists():
        print("promotion blocked: normalized shelter output is missing")
        return 2
    current_digest = sha256_directory(normalized_path)
    if current_digest != artifact["provenance"]["normalized_sha256"]:
        print("promotion blocked: inspection artifact is stale or shelter contents changed")
        return 2

    target = Path(policy.state_root) / "safe-camp" / artifact["inspection_id"]
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(normalized_path, target)
    artifact["status"] = "safe_camp"
    artifact["promotion"]["target_path"] = str(target.resolve())
    write_report(artifact, Path(args.report))
    print(f"promoted_to: {target}")
    return 0


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
    return 0 if result["valid"] else 2


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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
