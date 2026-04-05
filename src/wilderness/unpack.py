from __future__ import annotations

from dataclasses import dataclass, field
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import zipfile

from wilderness.common import has_control_chars, is_likely_binary, reset_directory, safe_display
from wilderness.intake import IntakeRecord, StateLayout
from wilderness.policy import Policy


@dataclass(slots=True)
class UnpackResult:
    shelter_path: Path
    normalized_output_path: Path
    findings: list[dict] = field(default_factory=list)
    file_count: int = 0
    expanded_size_bytes: int = 0


def _finding(family: str, severity: str, message: str, path: str | None = None) -> dict:
    finding = {"family": family, "severity": severity, "message": message}
    if path is not None:
        finding["path"] = path
    return finding


def _normalize_component(component: str, policy: Policy) -> str:
    cleaned = []
    for char in component:
        if ord(char) < 32 or ord(char) == 127:
            if policy.normalize_filenames:
                cleaned.append("_")
        else:
            cleaned.append(char)
    normalized = "".join(cleaned).strip() or "_"
    return normalized


def _normalize_archive_name(name: str, policy: Policy) -> tuple[Path, bool]:
    raw = PurePosixPath(name.replace("\\", "/"))
    if raw.is_absolute():
        raise ValueError("absolute path inside bundle")
    parts = []
    had_control = has_control_chars(name)
    for part in raw.parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError("path traversal inside bundle")
        parts.append(_normalize_component(part, policy))
    if not parts:
        raise ValueError("empty path after normalization")
    return Path(*parts), had_control


def _is_archive_bytes(data: bytes) -> bool:
    with io.BytesIO(data) as handle:
        try:
            if zipfile.is_zipfile(handle):
                return True
        finally:
            handle.seek(0)
        try:
            with tarfile.open(fileobj=handle, mode="r:*"):
                return True
        except tarfile.TarError:
            return False


def _is_symlink_tar(member: tarfile.TarInfo) -> bool:
    return member.issym() or member.islnk()


def _is_symlink_zip(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _check_extension(path: Path, policy: Policy) -> dict | None:
    suffix = path.suffix.lower()
    if policy.allowed_extensions and suffix and suffix not in set(policy.allowed_extensions):
        return _finding(
            "policy_block",
            "severe",
            f"extension {suffix} is not allowed by policy",
            str(path),
        )
    if suffix in set(policy.blocked_extensions):
        return _finding(
            "policy_block",
            "severe",
            f"extension {suffix} is blocked by policy",
            str(path),
        )
    return None


def _register_file(path: Path, data: bytes, seen_paths: set[Path], result: UnpackResult, policy: Policy) -> None:
    if path in seen_paths:
        result.findings.append(
            _finding("policy_block", "severe", "duplicate normalized path", str(path))
        )
        return
    seen_paths.add(path)
    result.file_count += 1
    result.expanded_size_bytes += len(data)
    if result.file_count > policy.max_file_count:
        result.findings.append(
            _finding("policy_block", "critical", "file count exceeds policy limit", str(path))
        )
    if result.expanded_size_bytes > policy.max_expanded_size_bytes:
        result.findings.append(
            _finding("decompression_risk", "critical", "expanded size exceeds policy limit", str(path))
        )
    if has_control_chars(str(path)):
        result.findings.append(
            _finding("control_sequence", "moderate", "control characters found in normalized path", str(path))
        )
    extension_finding = _check_extension(path, policy)
    if extension_finding:
        result.findings.append(extension_finding)
    target = result.normalized_output_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _materialize_bytes(
    rel_path: Path,
    data: bytes,
    depth: int,
    seen_paths: set[Path],
    result: UnpackResult,
    policy: Policy,
) -> None:
    if _is_archive_bytes(data):
        result.findings.append(
            _finding("nested_archive", "moderate", "nested archive discovered", str(rel_path))
        )
        if depth >= policy.max_nested_archive_depth:
            result.findings.append(
                _finding("nested_archive", "severe", "nested archive depth exceeds policy", str(rel_path))
            )
            _register_file(rel_path, data, seen_paths, result, policy)
            return
        nested_root = rel_path.with_suffix("")
        try:
            with io.BytesIO(data) as handle:
                if zipfile.is_zipfile(handle):
                    _extract_zip(
                        zipfile.ZipFile(handle),
                        nested_root,
                        depth + 1,
                        seen_paths,
                        result,
                        policy,
                    )
                    return
            with io.BytesIO(data) as handle:
                with tarfile.open(fileobj=handle, mode="r:*") as archive:
                    _extract_tar(archive, nested_root, depth + 1, seen_paths, result, policy)
                    return
        except (tarfile.TarError, zipfile.BadZipFile):
            result.findings.append(
                _finding("format_confusion", "severe", "archive bytes could not be safely unpacked", str(rel_path))
            )
            _register_file(rel_path, data, seen_paths, result, policy)
            return
    _register_file(rel_path, data, seen_paths, result, policy)
    if is_likely_binary(data) and rel_path.suffix.lower() in {"", ".txt", ".json", ".md", ".log"}:
        result.findings.append(
            _finding("binary_payload", "severe", "binary payload hidden behind a text-like path", str(rel_path))
        )


def _extract_tar(
    archive: tarfile.TarFile,
    prefix: Path,
    depth: int,
    seen_paths: set[Path],
    result: UnpackResult,
    policy: Policy,
) -> None:
    for member in archive.getmembers():
        if member.isdir():
            continue
        try:
            rel_path, had_control = _normalize_archive_name(member.name, policy)
        except ValueError as error:
            result.findings.append(
                _finding("archive_escape", "critical", str(error), safe_display(member.name))
            )
            continue
        full_rel = prefix / rel_path
        if had_control:
            result.findings.append(
                _finding("control_sequence", "moderate", "control characters found in archive member name", safe_display(member.name))
            )
        if _is_symlink_tar(member):
            result.findings.append(
                _finding("archive_escape", "critical", "symlink entry blocked", safe_display(member.name))
            )
            continue
        file_handle = archive.extractfile(member)
        if file_handle is None:
            continue
        _materialize_bytes(full_rel, file_handle.read(), depth, seen_paths, result, policy)


def _extract_zip(
    archive: zipfile.ZipFile,
    prefix: Path,
    depth: int,
    seen_paths: set[Path],
    result: UnpackResult,
    policy: Policy,
) -> None:
    for info in archive.infolist():
        if info.is_dir():
            continue
        try:
            rel_path, had_control = _normalize_archive_name(info.filename, policy)
        except ValueError as error:
            result.findings.append(
                _finding("archive_escape", "critical", str(error), safe_display(info.filename))
            )
            continue
        full_rel = prefix / rel_path
        if had_control:
            result.findings.append(
                _finding("control_sequence", "moderate", "control characters found in archive member name", safe_display(info.filename))
            )
        if _is_symlink_zip(info):
            result.findings.append(
                _finding("archive_escape", "critical", "symlink entry blocked", safe_display(info.filename))
            )
            continue
        _materialize_bytes(full_rel, archive.read(info), depth, seen_paths, result, policy)


def _copy_directory(
    source: Path,
    prefix: Path,
    depth: int,
    seen_paths: set[Path],
    result: UnpackResult,
    policy: Policy,
) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_dir():
            continue
        rel_source = path.relative_to(source)
        try:
            rel_path, had_control = _normalize_archive_name(rel_source.as_posix(), policy)
        except ValueError as error:
            result.findings.append(
                _finding("archive_escape", "critical", str(error), safe_display(rel_source.as_posix()))
            )
            continue
        full_rel = prefix / rel_path
        if had_control:
            result.findings.append(
                _finding("control_sequence", "moderate", "control characters found in source path", safe_display(rel_source.as_posix()))
            )
        if path.is_symlink():
            result.findings.append(
                _finding("archive_escape", "critical", "symlink entry blocked", safe_display(rel_source.as_posix()))
            )
            continue
        _materialize_bytes(full_rel, path.read_bytes(), depth, seen_paths, result, policy)


def build_shelter(intake: IntakeRecord, state: StateLayout, policy: Policy, out_path: str | None = None) -> UnpackResult:
    shelter_path = state.shelter / intake.inspection_id
    normalized_output_path = shelter_path / "normalized"
    reset_directory(shelter_path)
    normalized_output_path.mkdir(parents=True, exist_ok=True)
    result = UnpackResult(
        shelter_path=shelter_path,
        normalized_output_path=normalized_output_path,
    )
    seen_paths: set[Path] = set()

    if intake.provenance["raw_size_bytes"] > policy.max_raw_size_bytes:
        result.findings.append(
            _finding("oversize", "critical", "raw input exceeds policy limit")
        )

    if intake.quarantine_path.is_dir():
        _copy_directory(intake.quarantine_path, Path(), 0, seen_paths, result, policy)
    elif zipfile.is_zipfile(intake.quarantine_path):
        with zipfile.ZipFile(intake.quarantine_path) as archive:
            _extract_zip(archive, Path(), 0, seen_paths, result, policy)
    elif tarfile.is_tarfile(intake.quarantine_path):
        with tarfile.open(intake.quarantine_path, mode="r:*") as archive:
            _extract_tar(archive, Path(), 0, seen_paths, result, policy)
    else:
        try:
            rel_path, had_control = _normalize_archive_name(intake.quarantine_path.name, policy)
        except ValueError as error:
            result.findings.append(_finding("archive_escape", "critical", str(error)))
        else:
            if had_control:
                result.findings.append(
                    _finding("control_sequence", "moderate", "control characters found in source path", safe_display(intake.quarantine_path.name))
                )
            _materialize_bytes(rel_path, intake.quarantine_path.read_bytes(), 0, seen_paths, result, policy)

    if out_path:
        destination = Path(out_path).expanduser().resolve()
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(normalized_output_path, destination)

    return result
