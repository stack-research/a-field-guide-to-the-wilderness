from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path


CONTROL_CHARS = {chr(value) for value in range(32)} | {chr(127)}
SAFE_WHITESPACE = {"\n", "\r", "\t"}
TEXT_EXTENSIONS = {
    ".txt",
    ".json",
    ".md",
    ".log",
    ".csv",
    ".xml",
    ".yaml",
    ".yml",
    ".toml",
}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_directory(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        digest.update(str(path.relative_to(root)).encode("utf-8"))
        digest.update(sha256_file(path).encode("ascii"))
    return digest.hexdigest()


def total_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    size = 0
    for candidate in path.rglob("*"):
        if candidate.is_symlink():
            size += len(os.readlink(candidate))
        elif candidate.is_file():
            size += candidate.stat().st_size
    return size


def safe_display(value: str) -> str:
    return value.encode("unicode_escape").decode("ascii")


def has_control_chars(value: str) -> bool:
    return any(char in CONTROL_CHARS and char not in SAFE_WHITESPACE for char in value)


def read_bytes(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read()


def is_likely_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        pass
    sample = data[:4096]
    non_text = sum(
        1
        for byte in sample
        if byte < 9 or (13 < byte < 32) or byte > 126
    )
    return non_text / len(sample) > 0.30


def dump_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def reset_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
