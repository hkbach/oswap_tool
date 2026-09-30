"""Load and validate the declarative check tables in ``owasp_scanner/rules/`` (NFR-MAINT-02, FR-EXP-01).

Rules are plain JSON (no extra dependency). Each file carries a ``version``; the
scan report's ``rules_version`` comes from here, so a report says which rule set
produced it.
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from pathlib import Path

from .models import Severity

RULES_DIR = Path(__file__).with_name("rules")
_SENSITIVE_PATHS_FILE = RULES_DIR / "sensitive_paths.json"
_REQUIRED_PATH_FIELDS = ("path", "id", "severity", "title")


@dataclass(frozen=True)
class SensitivePath:
    path: str
    id: str
    severity: Severity
    title: str


@dataclass(frozen=True)
class SensitivePathRules:
    version: str
    paths: tuple[SensitivePath, ...]


def _fail(source: Path, message: str) -> None:
    raise ValueError(f"{source.name}: {message}")


def _parse_sensitive_paths(source: Path) -> SensitivePathRules:
    data = json.loads(source.read_text(encoding="utf-8"))
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        _fail(source, "missing or empty 'version'")
    entries = data.get("paths")
    if not isinstance(entries, list) or not entries:
        _fail(source, "'paths' must be a non-empty list")

    paths: list[SensitivePath] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for n, entry in enumerate(entries, 1):
        for key in _REQUIRED_PATH_FIELDS:
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                _fail(source, f"entry {n}: missing or empty '{key}'")
        path, finding_id = entry["path"], entry["id"]
        if path.startswith("/") or "://" in path:
            _fail(source, f"entry {n}: path {path!r} must be relative to the target")
        if entry["severity"] not in Severity.__members__:
            _fail(source, f"entry {n}: unknown severity {entry['severity']!r}")
        if finding_id in seen_ids:
            _fail(source, f"entry {n}: duplicate id {finding_id!r}")
        if path in seen_paths:
            _fail(source, f"entry {n}: duplicate path {path!r}")
        seen_ids.add(finding_id)
        seen_paths.add(path)
        paths.append(SensitivePath(path, finding_id, Severity[entry["severity"]], entry["title"]))
    return SensitivePathRules(version.strip(), tuple(paths))


@functools.cache
def _load_cached(source: Path) -> SensitivePathRules:
    return _parse_sensitive_paths(source)


def load_sensitive_paths(source: Path | None = None) -> SensitivePathRules:
    """The sensitive-path table; the bundled file unless ``source`` is given."""
    return _load_cached(source or _SENSITIVE_PATHS_FILE)


def rules_version() -> str:
    """Version of the bundled rule set, reported as ``rules_version``."""
    return load_sensitive_paths().version
