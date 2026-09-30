"""README consistency checks that do not fit any single FR (FR-DOC-01).

Written after two staleness bugs were found by hand during the Sprint 9 README
review: the AT-count range and the branch-protection check list both drift
silently whenever the SRS or the CI workflow changes without updating README too.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_readme_at_range_matches_the_srs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    srs = (ROOT / "docs" / "SRS-owasp-scanner.md").read_text(encoding="utf-8")

    stated = re.search(r"acceptance scenarios AT-01 to AT-(\d+)", readme)
    assert stated, "README must say which AT- range the test suite covers"
    at_numbers = [int(n) for n in re.findall(r"^\| AT-(\d+) \|", srs, flags=re.MULTILINE)]
    assert int(stated.group(1)) == max(at_numbers)


def _workflow_required_checks() -> set[str]:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    jobs_section = workflow[workflow.index("\njobs:\n") :]  # "on:"/"push:" also match at 2 spaces
    jobs = set(re.findall(r"^  ([a-z-]+):$", jobs_section, flags=re.MULTILINE))
    jobs.discard("test")  # fans out into one check per matrix entry, not its own check
    matrix = re.findall(r'\{ os: ([\w.-]+), python: "([\d.]+)" \}', workflow)
    assert matrix, "could not find the test job's matrix entries"
    return jobs | {f"test ({os}, {python})" for os, python in matrix}


def test_readme_required_checks_list_matches_the_workflow():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    required = _workflow_required_checks()

    listed_block = re.search(r"Required checks:\n\n```text\n(.*?)\n```", readme, re.DOTALL)
    assert listed_block, "README must list the required checks in a fenced text block"
    assert set(listed_block.group(1).splitlines()) == required

    gh_api = re.search(r'"contexts": \[\n(.*?)\n\s*\]', readme, re.DOTALL)
    assert gh_api, "README must show the gh api contexts list"
    listed_contexts = set(re.findall(r'"([^"]+)"', gh_api.group(1)))
    assert listed_contexts == required
