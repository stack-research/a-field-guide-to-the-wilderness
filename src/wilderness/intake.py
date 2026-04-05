from __future__ import annotations

from dataclasses import dataclass
import shutil
from pathlib import Path
from uuid import uuid4
import tarfile
import zipfile

from wilderness.policy import Policy
from wilderness.provenance import initial_provenance


@dataclass(slots=True)
class StateLayout:
    root: Path
    quarantine: Path
    shelter: Path
    reports: Path
    history: Path
    discard: Path
    safe_camp: Path


@dataclass(slots=True)
class IntakeRecord:
    inspection_id: str
    source_path: Path
    quarantine_path: Path
    artifact_type: str
    provenance: dict


def ensure_state(root: Path) -> StateLayout:
    layout = StateLayout(
        root=root,
        quarantine=root / "quarantine",
        shelter=root / "shelter",
        reports=root / "reports",
        history=root / "history",
        discard=root / "discard",
        safe_camp=root / "safe-camp",
    )
    for path in (
        layout.root,
        layout.quarantine,
        layout.shelter,
        layout.reports,
        layout.history,
        layout.discard,
        layout.safe_camp,
    ):
        path.mkdir(parents=True, exist_ok=True)
    return layout


def identify_input_type(path: Path) -> str:
    if path.is_dir():
        return "directory"
    if zipfile.is_zipfile(path):
        return "zip"
    if tarfile.is_tarfile(path):
        return "tar"
    if path.suffix.lower() == ".json":
        return "json_file"
    return "file"


def _copy_source(source: Path, destination: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, destination, symlinks=True)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def retain_discard_copy(quarantine_path: Path, state: StateLayout, inspection_id: str) -> Path:
    discard_path = state.discard / inspection_id / "raw" / quarantine_path.name
    if discard_path.exists():
        if discard_path.is_dir():
            shutil.rmtree(discard_path)
        else:
            discard_path.unlink()
    _copy_source(quarantine_path, discard_path)
    return discard_path


def land_input(source: str, policy: Policy) -> tuple[IntakeRecord, StateLayout]:
    source_path = Path(source).expanduser().resolve()
    if not source_path.exists():
        raise FileNotFoundError(source)

    state = ensure_state(Path.cwd() / policy.state_root)
    inspection_id = uuid4().hex
    artifact_type = identify_input_type(source_path)
    quarantine_path = state.quarantine / inspection_id / source_path.name
    _copy_source(source_path, quarantine_path)

    provenance = initial_provenance(source_path, quarantine_path)
    record = IntakeRecord(
        inspection_id=inspection_id,
        source_path=source_path,
        quarantine_path=quarantine_path,
        artifact_type=artifact_type,
        provenance=provenance,
    )
    return record, state
