from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
import tomllib

from wilderness.common import sha256_bytes

_SUSPICIOUS_TEXT_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL
_ALLOWED_SEVERITIES = {"low", "moderate", "severe", "critical"}
_ALLOWED_TOP_LEVEL_KEYS = {
    "state_root",
    "max_raw_size_bytes",
    "max_expanded_size_bytes",
    "max_file_count",
    "max_nested_archive_depth",
    "max_line_length",
    "allowed_extensions",
    "blocked_extensions",
    "normalize_filenames",
    "block_control_characters",
    "promotion_blocking_severities",
    "suspicious_text_enabled",
    "suspicious_text_max_bytes",
    "suspicious_text_max_findings_per_file",
    "suspicious_text_snippet_chars",
    "suspicious_text_window_lines",
    "suspicious_text_rule_packs",
    "suspicious_text_block_all",
    "suspicious_text_block_rule_ids",
    "manifest_required_for_promotion",
    "manifest_free_fallback_enabled",
    "manifest_free_fallback_scope",
    "discard_retention_enabled",
    "discard_copy_mode",
    "redaction_required",
    "redaction",
}
_ALLOWED_REDACTION_KEYS = {"enabled", "redact_paths", "redact_secrets"}
_STRING_LIST_FIELDS = {
    "allowed_extensions",
    "blocked_extensions",
    "suspicious_text_rule_packs",
    "suspicious_text_block_rule_ids",
}
_BOOLEAN_FIELDS = {
    "normalize_filenames",
    "block_control_characters",
    "suspicious_text_enabled",
    "suspicious_text_block_all",
    "manifest_required_for_promotion",
    "manifest_free_fallback_enabled",
    "discard_retention_enabled",
    "redaction_required",
}
_POSITIVE_INTEGER_FIELDS = {
    "max_raw_size_bytes",
    "max_expanded_size_bytes",
    "max_file_count",
    "max_line_length",
    "suspicious_text_max_bytes",
    "suspicious_text_max_findings_per_file",
    "suspicious_text_snippet_chars",
}
_NON_NEGATIVE_INTEGER_FIELDS = {
    "max_nested_archive_depth",
    "suspicious_text_window_lines",
}
_ENUM_FIELDS = {
    "manifest_free_fallback_scope": {"single_file_text_or_json"},
    "discard_copy_mode": {"copy"},
}


class PolicyValidationError(ValueError):
    pass


@dataclass(slots=True)
class RulePackInfo:
    path: str
    sha256: str
    rule_count: int


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
    suspicious_text_window_lines: int = 1
    suspicious_text_rule_packs: list[str] = field(default_factory=list)
    suspicious_text_block_all: bool = False
    suspicious_text_block_rule_ids: list[str] = field(default_factory=list)
    manifest_required_for_promotion: bool = True
    manifest_free_fallback_enabled: bool = False
    manifest_free_fallback_scope: str = "single_file_text_or_json"
    discard_retention_enabled: bool = False
    discard_copy_mode: str = "copy"
    redaction_required: bool = False
    redaction: RedactionPolicy = field(default_factory=RedactionPolicy)
    source_path: str | None = field(default=None, repr=False)
    loaded_rule_packs: list[RulePackInfo] = field(default_factory=list, repr=False)

    def snapshot(self) -> dict:
        data = asdict(self)
        data.pop("source_path", None)
        data.pop("loaded_rule_packs", None)
        return data


def _require_type(value: object, expected_type: type, field_name: str, label: str) -> None:
    if type(value) is not expected_type:
        raise PolicyValidationError(f"{field_name} must be a {label}")


def _validate_string_list(values: object, field_name: str) -> list[str]:
    if not isinstance(values, list):
        raise PolicyValidationError(f"{field_name} must be a list")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value:
            raise PolicyValidationError(f"{field_name} entries must be non-empty strings")
        normalized.append(value)
    return normalized


def _validate_suspicious_pattern(pattern: str, context: str) -> None:
    try:
        re.compile(pattern, _SUSPICIOUS_TEXT_FLAGS)
    except re.error as error:
        raise PolicyValidationError(f"{context}: invalid regex: {error}") from error


def validate_suspicious_rule_definition(raw_rule: object, context: str) -> dict:
    if not isinstance(raw_rule, dict):
        raise PolicyValidationError(f"{context}: rule must be a table")
    rule_id = raw_rule.get("id")
    pattern = raw_rule.get("pattern")
    if not isinstance(rule_id, str) or not rule_id:
        raise PolicyValidationError(f"{context}: rule id must be a non-empty string")
    if not isinstance(pattern, str) or not pattern:
        raise PolicyValidationError(f"{context}: rule pattern must be a non-empty string")
    description = raw_rule.get("description")
    if description is not None and not isinstance(description, str):
        raise PolicyValidationError(f"{context}: description must be a string")
    exclude_pattern = raw_rule.get("exclude_pattern")
    if exclude_pattern is not None and not isinstance(exclude_pattern, str):
        raise PolicyValidationError(f"{context}: exclude_pattern must be a string")
    window_lines = raw_rule.get("window_lines")
    if window_lines is not None and (type(window_lines) is not int or window_lines < 0):
        raise PolicyValidationError(f"{context}: window_lines must be a non-negative integer")
    _validate_suspicious_pattern(pattern, context)
    if exclude_pattern is not None:
        _validate_suspicious_pattern(exclude_pattern, context)
    return {
        "id": rule_id,
        "pattern": pattern,
        "description": description,
        "exclude_pattern": exclude_pattern,
        "window_lines": window_lines,
    }


def resolve_rule_pack_path(pack_path: str, policy: Policy) -> Path:
    candidate = Path(pack_path).expanduser()
    if candidate.is_absolute():
        return candidate
    if policy.source_path:
        return Path(policy.source_path).parent / candidate
    return Path.cwd() / candidate


def load_rule_pack_definition(pack_path: Path) -> RulePackInfo:
    try:
        raw_bytes = pack_path.read_bytes()
    except OSError as error:
        message = error.strerror or str(error)
        raise PolicyValidationError(
            f"unable to read suspicious-text rule pack {pack_path}: {message}"
        ) from error
    try:
        raw = tomllib.loads(raw_bytes.decode("utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise PolicyValidationError(f"invalid suspicious-text rule pack {pack_path}: {error}") from error
    except UnicodeDecodeError as error:
        raise PolicyValidationError(f"invalid suspicious-text rule pack {pack_path}: {error}") from error

    if raw.get("schema_version") != 1:
        raise PolicyValidationError(
            f"invalid suspicious-text rule pack {pack_path}: schema_version must be 1"
        )
    rules = raw.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PolicyValidationError(
            f"invalid suspicious-text rule pack {pack_path}: rules must be a non-empty list"
        )
    seen_rule_ids: set[str] = set()
    for index, raw_rule in enumerate(rules, start=1):
        rule = validate_suspicious_rule_definition(raw_rule, f"{pack_path} rule {index}")
        if rule["id"] in seen_rule_ids:
            raise PolicyValidationError(
                f"invalid suspicious-text rule pack {pack_path}: duplicate rule id {rule['id']}"
            )
        seen_rule_ids.add(rule["id"])
    return RulePackInfo(
        path=str(pack_path.resolve()),
        sha256=sha256_bytes(raw_bytes),
        rule_count=len(rules),
    )


def _validate_top_level_keys(raw: dict) -> None:
    unknown = sorted(set(raw) - _ALLOWED_TOP_LEVEL_KEYS)
    if unknown:
        raise PolicyValidationError(f"unknown policy field: {unknown[0]}")


def _validate_redaction_keys(raw_redaction: object) -> None:
    if raw_redaction is None:
        return
    if not isinstance(raw_redaction, dict):
        raise PolicyValidationError("redaction must be a table")
    unknown = sorted(set(raw_redaction) - _ALLOWED_REDACTION_KEYS)
    if unknown:
        raise PolicyValidationError(f"unknown redaction policy field: {unknown[0]}")


def _validate_policy_shape(policy: Policy) -> None:
    if not isinstance(policy.state_root, str) or not policy.state_root:
        raise PolicyValidationError("state_root must be a non-empty string")
    for field_name in _BOOLEAN_FIELDS:
        _require_type(getattr(policy, field_name), bool, field_name, "boolean")
    for field_name in _POSITIVE_INTEGER_FIELDS:
        value = getattr(policy, field_name)
        if type(value) is not int or value <= 0:
            raise PolicyValidationError(f"{field_name} must be a positive integer")
    for field_name in _NON_NEGATIVE_INTEGER_FIELDS:
        value = getattr(policy, field_name)
        if type(value) is not int or value < 0:
            raise PolicyValidationError(f"{field_name} must be a non-negative integer")
    for field_name, allowed in _ENUM_FIELDS.items():
        value = getattr(policy, field_name)
        if not isinstance(value, str) or value not in allowed:
            allowed_text = " or ".join(f"'{item}'" for item in sorted(allowed))
            raise PolicyValidationError(f"{field_name} must be {allowed_text}")
    for field_name in _STRING_LIST_FIELDS:
        setattr(policy, field_name, _validate_string_list(getattr(policy, field_name), field_name))

    severities = _validate_string_list(policy.promotion_blocking_severities, "promotion_blocking_severities")
    invalid_severities = [severity for severity in severities if severity not in _ALLOWED_SEVERITIES]
    if invalid_severities:
        raise PolicyValidationError(
            "promotion_blocking_severities entries must be one of 'low', 'moderate', 'severe', 'critical'"
        )
    policy.promotion_blocking_severities = severities

    if len(set(policy.suspicious_text_block_rule_ids)) != len(policy.suspicious_text_block_rule_ids):
        raise PolicyValidationError("suspicious_text_block_rule_ids entries must be unique")
    if policy.manifest_free_fallback_enabled and not policy.manifest_required_for_promotion:
        raise PolicyValidationError(
            "manifest_free_fallback_enabled requires manifest_required_for_promotion to stay true"
        )

    redaction = policy.redaction
    _require_type(redaction.enabled, bool, "redaction.enabled", "boolean")
    _require_type(redaction.redact_paths, bool, "redaction.redact_paths", "boolean")
    _require_type(redaction.redact_secrets, bool, "redaction.redact_secrets", "boolean")


def _validate_loaded_rule_packs(policy: Policy) -> None:
    loaded_packs: list[RulePackInfo] = []
    seen_paths: set[str] = set()
    for pack in policy.suspicious_text_rule_packs:
        resolved_path = str(resolve_rule_pack_path(pack, policy).resolve())
        if resolved_path in seen_paths:
            raise PolicyValidationError(f"suspicious_text_rule_packs entries must be unique: {resolved_path}")
        seen_paths.add(resolved_path)
        loaded_packs.append(load_rule_pack_definition(Path(resolved_path)))
    policy.loaded_rule_packs = loaded_packs


def _merge_redaction(policy: Policy, data: dict) -> None:
    raw_redaction = data.get("redaction")
    if raw_redaction is None:
        return
    for key, value in raw_redaction.items():
        setattr(policy.redaction, key, value)


def load_policy(path: str | None) -> Policy:
    policy = Policy()
    raw: dict = {}
    if path:
        policy_path = Path(path).expanduser().resolve()
        raw = tomllib.loads(policy_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise PolicyValidationError("policy file must decode to a table")
        _validate_top_level_keys(raw)
        _validate_redaction_keys(raw.get("redaction"))
        for key, value in raw.items():
            if key == "redaction":
                continue
            setattr(policy, key, value)
        _merge_redaction(policy, raw)
        policy.source_path = str(policy_path)
    _validate_policy_shape(policy)
    _validate_loaded_rule_packs(policy)
    return policy
