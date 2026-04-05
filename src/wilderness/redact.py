from __future__ import annotations

import re

from wilderness.policy import Policy


SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]
POSIX_PATH_RE = re.compile(r"/(?:Users|home)/[^\s\"']+")
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")


def redact_text(text: str, policy: Policy) -> str:
    redacted = text
    if policy.redaction.redact_secrets:
        for pattern in SECRET_PATTERNS:
            redacted = pattern.sub(lambda match: f"{match.group(1)}=<redacted>" if match.groups() else "<redacted-secret>", redacted)
    if policy.redaction.redact_paths:
        redacted = POSIX_PATH_RE.sub("<redacted-path>", redacted)
        redacted = WINDOWS_PATH_RE.sub("<redacted-path>", redacted)
    return redacted


def redact_bytes(data: bytes, policy: Policy) -> tuple[bytes, bool]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, False
    redacted = redact_text(text, policy).encode("utf-8")
    return redacted, redacted != data
