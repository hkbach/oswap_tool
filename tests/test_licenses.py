"""FR-SEC-10: THIRD_PARTY_LICENSES.md stays in sync with pyproject.toml's direct dependencies.

This does not re-verify license text or re-resolve versions (see that file's own "Checking
again" note for the manual steps); it only catches a dependency being added, removed or
renamed in pyproject.toml without the inventory being updated to match.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _package_name(requirement: str) -> str:
    # "requests>=2.32.3" / "ruff>=0.14,<0.15"  ->  "requests" / "ruff"
    return re.split(r"[<>=!~\[]", requirement, maxsplit=1)[0].strip().lower()


def _declared_dependencies() -> tuple[set[str], set[str], set[str]]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    runtime = {_package_name(r) for r in project["dependencies"]}
    dev = {_package_name(r) for r in project["optional-dependencies"]["dev"]}
    service = {_package_name(r) for r in project["optional-dependencies"]["service"]}
    return runtime, dev, service


_ROW = re.compile(r"^\|\s*([\w.-]+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|$")


def _inventory_rows() -> list[tuple[str, str, str]]:
    """Every (package, license, "direct dependency of") data row of the two tables."""
    text = (ROOT / "THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8")
    rows = (_ROW.match(line) for line in text.splitlines())
    return [(m.group(1).lower(), m.group(2), m.group(3)) for m in rows if m and m.group(1) != "Package"]


def _inventoried_direct_dependencies() -> tuple[set[str], set[str], set[str]]:
    runtime, dev, service = set(), set(), set()
    for package, _license, owner in _inventory_rows():
        entries = {o.strip() for o in owner.split(",")}
        if "this project" in entries:
            runtime.add(package)
        if "this project (dev)" in entries:
            dev.add(package)
        if "this project (service)" in entries:
            service.add(package)
    return runtime, dev, service


def test_third_party_licenses_lists_every_direct_dependency():
    declared_runtime, declared_dev, declared_service = _declared_dependencies()
    listed_runtime, listed_dev, listed_service = _inventoried_direct_dependencies()
    assert listed_runtime == declared_runtime
    assert listed_dev == declared_dev
    assert listed_service == declared_service


def test_third_party_licenses_has_no_copyleft_that_would_force_releasing_source():
    # Only the License column of each row, not the surrounding prose (which explains, by
    # name, why none of these licenses are copyleft in that sense).
    for package, license_field, _owner in _inventory_rows():
        for forbidden in ("GPL", "AGPL", "LGPL"):
            assert forbidden not in license_field, f"{package}: {license_field!r} looks copyleft"
