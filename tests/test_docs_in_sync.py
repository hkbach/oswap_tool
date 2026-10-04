"""The documentation must describe exactly the options the tools have.

Options added in one sprint were left out of the README and SRS tables for two or three
sprints before anyone noticed. These tests make that impossible: every option the CLI and the
Web UI accept must be in their option tables, and every option a table lists must exist.
"""

from __future__ import annotations

import contextlib
import io
import re
from pathlib import Path

import pytest

from websec_scanner import cli, web

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
SRS = (ROOT / "docs" / "SRS-websec-scanner.md").read_text(encoding="utf-8")
_OPTION = re.compile(r"--[a-z][a-z0-9-]*")


def _section(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin : text.index(end, begin + len(start))]


def _table_options(section: str) -> set[str]:
    """Options named in the first column of a Markdown table (the column that defines them)."""
    found = set()
    for line in section.splitlines():
        if line.startswith("|") and not line.startswith("|---"):
            found |= set(_OPTION.findall(line.split("|")[1]))
    return found


def _cli_options() -> set[str]:
    return {opt for action in cli.build_parser()._actions for opt in action.option_strings if opt.startswith("--")} - {
        "--help"
    }


def _web_options() -> set[str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), pytest.raises(SystemExit):
        web.main(["--help"])
    return set(_OPTION.findall(out.getvalue())) - {"--help"}


DOCUMENTS = {
    "README CLI option table": (lambda: _section(README, "## Usage", "### Exit codes"), _cli_options),
    "SRS 7.2 CLI option table": (lambda: _section(SRS, "### 7.2", "### 7.3"), _cli_options),
    "README web UI section": (lambda: _section(README, "## Local web UI", "## Development"), _web_options),
    "SRS 7.4 web UI table": (lambda: _section(SRS, "### 7.4", "\n## "), _web_options),
}


@pytest.mark.parametrize("document", sorted(DOCUMENTS))
def test_every_option_is_documented(document):
    section, options = DOCUMENTS[document]
    missing = options() - _table_options(section())
    assert not missing, f"{document} does not document: {sorted(missing)}"


@pytest.mark.parametrize("document", sorted(DOCUMENTS))
def test_every_documented_option_exists(document):
    section, options = DOCUMENTS[document]
    stale = _table_options(section()) - options()
    assert not stale, f"{document} documents options the tool does not have: {sorted(stale)}"


def _at_rows() -> list[tuple[str, str]]:
    """(AT id, evidence column) for every row of the acceptance-test table in SRS section 9."""
    rows = []
    for line in SRS.splitlines():
        if line.startswith("| AT-"):
            cells = [cell.strip() for cell in line.split("|")]
            rows.append((cells[1], cells[-2]))
    return rows


def test_the_acceptance_table_was_found():
    # If the table moved or its format changed, the two tests below would pass vacuously.
    assert len(_at_rows()) >= 70


@pytest.mark.parametrize("at_id, evidence", _at_rows(), ids=[row[0] for row in _at_rows()])
def test_every_test_named_by_an_acceptance_row_exists(at_id, evidence):
    """AT-47 named a test that had been renamed two sprints earlier; nobody noticed."""
    source = "\n".join(path.read_text(encoding="utf-8") for path in sorted(Path(__file__).parent.glob("test_*.py")))
    named = set(re.findall(r"`(test_[a-z0-9_]+)`", evidence))
    missing = sorted(name for name in named if f"def {name}(" not in source)
    assert not missing, f"{at_id} names tests that do not exist: {missing}"


@pytest.mark.parametrize("at_id, evidence", _at_rows(), ids=[row[0] for row in _at_rows()])
def test_every_test_file_named_by_an_acceptance_row_exists(at_id, evidence):
    files = set(re.findall(r"`?(tests/test_[a-z0-9_]+\.py)`?", evidence))
    missing = sorted(name for name in files if not (ROOT / name).exists())
    assert not missing, f"{at_id} names test files that do not exist: {missing}"


def test_every_acceptance_row_cites_evidence():
    empty = [at_id for at_id, evidence in _at_rows() if not re.search(r"test_[a-z0-9_]+", evidence)]
    assert not empty, f"these acceptance rows name no test: {empty}"


def test_the_version_in_the_readme_install_commands_is_the_current_release():
    from websec_scanner import __version__

    pinned = set(re.findall(r"oswap_tool(?:@|/archive/refs/tags/)v(\d+\.\d+\.\d+)", README))
    assert pinned == {__version__}, f"README pins {sorted(pinned)}, the package is {__version__}"
