from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import tomllib


@dataclass(slots=True)
class RedactionPolicy:
    enabled: bool = False
    redact_paths: bool = True
    redact_secrets: bool = True


@dataclass(slots=True)
class Policy:
    state_root: str = ".wilderness"
    max_raw_size_bytes: int = 25 * 1024 * 1024
    max_expanded_size_bytes: int = 50 * 1024 * 1024
    max_file_count: int = 500
    max_nested_archive_depth: int = 1
    max_line_length: int = 20_000
    allowed_extensions: list[str] = field(default_factory=list)
    blocked_extensions: list[str] = field(
        default_factory=lambda: [".exe", ".dll", ".so", ".dylib", ".pyc"]
    )
    normalize_filenames: bool = True
    block_control_characters: bool = True
    promotion_blocking_severities: list[str] = field(
        default_factory=lambda: ["severe", "critical"]
    )
    suspicious_text_enabled: bool = True
    suspicious_text_max_bytes: int = 262_144
    suspicious_text_max_findings_per_file: int = 5
    suspicious_text_snippet_chars: int = 96
    redaction_required: bool = False
    redaction: RedactionPolicy = field(default_factory=RedactionPolicy)

    def snapshot(self) -> dict:
        return asdict(self)


def _merge_redaction(policy: Policy, data: dict) -> None:
    if "redaction" not in data:
        return
    for key, value in data["redaction"].items():
        setattr(policy.redaction, key, value)


def load_policy(path: str | None) -> Policy:
    policy = Policy()
    if not path:
        return policy

    raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    for key, value in raw.items():
        if key == "redaction":
            continue
        setattr(policy, key, value)
    _merge_redaction(policy, raw)
    return policy
