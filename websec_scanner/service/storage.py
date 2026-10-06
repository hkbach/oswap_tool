"""Where scan results are kept: one JSON file per scan under ``results/`` (decision D12). Standard library only.

``results/<agency_id>/<client_id>/<year>/<month>/<scan_id>.json``. Every part of the path comes from an id the service
made and checked, never from caller input, and the path is checked to stay inside the results folder. A file is written
to a temporary name and renamed, so a reader never sees half a report and a crash leaves no broken file behind.
"""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import ids


class StorageError(Exception):
    """A result path that is not one of the service's own (a wrong kind of id, or a path leaving the folder)."""


def _inside(results_dir: Path, path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(results_dir.resolve()):
        raise StorageError("path outside the results folder")
    return resolved


def relative_path(agency_id: str, client_id: str, scan_id: str) -> str:
    """The path of a scan's result, relative to the results folder, with forward slashes."""
    for kind, value in (("agency", agency_id), ("client", client_id), ("scan", scan_id)):
        if not ids.is_valid(kind, value):
            raise StorageError(f"not a valid {kind} id")
    when = datetime.fromtimestamp(ids.created_ms(scan_id) / 1000, tz=UTC)
    return f"{agency_id}/{client_id}/{when:%Y}/{when:%m}/{scan_id}.json"


def write_report(results_dir: Path, agency_id: str, client_id: str, scan_id: str, content: bytes) -> str:
    """Store ``content`` and return its relative path."""
    relative = relative_path(agency_id, client_id, scan_id)
    target = _inside(Path(results_dir), Path(results_dir) / relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=target.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return relative


def read_report(results_dir: Path, relative: str) -> bytes:
    return _inside(Path(results_dir), Path(results_dir) / relative).read_bytes()
