"""FR-CI-03: the CI templates call the real CLI with options that exist.

The templates are not executed here (no CI system offline); these tests only keep
them consistent with the CLI and the release.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from websec_scanner import __version__, cli

TEMPLATES = sorted((Path(__file__).resolve().parents[1] / "examples" / "ci").iterdir())


def _scan_command(text: str) -> str:
    start = text.index("python -m websec_scanner")
    lines = []
    for line in text[start:].splitlines():
        if lines and "--" not in line:
            break
        lines.append(line)
    return " ".join(lines)


@pytest.fixture(scope="module")
def cli_help() -> str:
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), pytest.raises(SystemExit):
        cli.main(["--help"])
    return buffer.getvalue()


def test_all_four_templates_exist():
    assert {p.name for p in TEMPLATES} == {"github-actions.yml", "gitlab-ci.yml", "azure-pipelines.yml", "Jenkinsfile"}


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_template_uses_only_real_cli_options(template, cli_help):
    command = _scan_command(template.read_text(encoding="utf-8"))
    flags = set(re.findall(r"(?<![\w-])--[a-z][a-z-]+", command))
    assert {"--yes", "--fail-on", "--json", "--sarif", "--html"} <= flags
    for flag in flags:
        assert flag in cli_help, f"{template.name}: {flag} is not a CLI option"


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_template_warns_about_authorization_and_exit_codes(template):
    text = template.read_text(encoding="utf-8")
    assert "authorized to test" in text
    assert "3 target could not be scanned" in text


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_template_installs_the_current_release(template):
    text = template.read_text(encoding="utf-8")
    assert f"v{__version__}" in text, f"{template.name}: SCANNER_REF must follow the release version"
    installs_via_git = "git+https://github.com/hkbach/oswap_tool@" in text
    installs_via_archive = "github.com/hkbach/oswap_tool/archive/refs/tags/" in text
    assert installs_via_git or installs_via_archive


def test_jenkinsfile_installs_from_the_source_archive_not_git():
    # Jenkins' Docker Pipeline plugin runs the agent container as a non-root user by default,
    # so `apt-get install git` (needed for a git+https install, like the other three templates
    # use) used to fail here. The tagged source archive over plain HTTPS needs neither.
    text = next(p for p in TEMPLATES if p.name == "Jenkinsfile").read_text(encoding="utf-8")
    assert "archive/refs/tags/" in text
    assert "sh 'apt-get" not in text  # a comment may still explain why, that's fine
    assert "git+https" not in text


@pytest.mark.parametrize("template", [p for p in TEMPLATES if p.suffix == ".yml"], ids=lambda p: p.name)
def test_yaml_templates_have_no_tabs(template):
    assert "\t" not in template.read_text(encoding="utf-8")
