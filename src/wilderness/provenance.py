from __future__ import annotations

from pathlib import Path

from wilderness.common import sha256_directory, sha256_file, total_size, utc_now


def record_input_ref(source: Path) -> dict:
    return {
        "source_path": str(source.resolve()),
        "source_name": source.name,
        "source_kind": "directory" if source.is_dir() else "file",
    }


def record_quarantine_ref(path: Path) -> dict:
    return {
        "quarantine_path": str(path.resolve()),
        "quarantine_kind": "directory" if path.is_dir() else "file",
    }


def raw_material_hash(path: Path) -> str:
    return sha256_directory(path) if path.is_dir() else sha256_file(path)


def raw_material_size(path: Path) -> int:
    return total_size(path)


def initial_provenance(source: Path, quarantine_path: Path) -> dict:
    return {
        "received_at": utc_now(),
        "input": record_input_ref(source),
        "quarantine": record_quarantine_ref(quarantine_path),
        "raw_sha256": raw_material_hash(quarantine_path),
        "raw_size_bytes": raw_material_size(quarantine_path),
    }
