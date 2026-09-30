"""FR-CI-04: the official Docker image, checked at the file level.

Docker is not available in this environment (see CLAUDE.md dev notes), so the image itself
is only built and smoke-tested in CI (.github/workflows/ci.yml, job "docker"); these tests
keep the Dockerfile consistent with the project (correct entrypoint, non-root user, no stray
build artifacts left in the final stage).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _dockerfile() -> str:
    return (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_dockerfile_exists_and_is_two_stage():
    text = _dockerfile()
    assert text.count("FROM python:3.12-slim") == 2, "expected a build stage and a final stage"
    assert "AS build" in text


def test_dockerfile_runs_as_a_non_root_user():
    text = _dockerfile()
    match = re.search(r"^USER (\S+)$", text, flags=re.MULTILINE)
    assert match and match.group(1) != "root"
    # useradd must appear before USER switches to it, with a non-zero uid.
    assert re.search(r"useradd .*--uid \d+", text)


def test_dockerfile_entrypoint_is_the_cli():
    assert 'ENTRYPOINT ["python", "-m", "websec_scanner"]' in _dockerfile()


def test_dockerfile_final_stage_does_not_copy_the_source_tree():
    # Only the build stage should COPY the repo; the final stage copies the installed
    # package from the build stage (no source, no pyproject.toml, no compiler left behind).
    text = _dockerfile()
    final_stage = text[text.index("FROM python:3.12-slim\n", text.index("AS build") + 1) :]
    assert "COPY websec_scanner" not in final_stage
    assert "COPY --from=build" in final_stage


def test_dockerfile_has_oci_source_label_but_no_unverified_license_claim():
    # GHCR links a published package to its repo via this label; the project has no
    # declared license yet, so the image must not claim one (see docs/PRODUCT-BACKLOG.md).
    text = _dockerfile()
    assert 'org.opencontainers.image.source="https://github.com/hkbach/oswap_tool"' in text
    assert "LABEL org.opencontainers.image.licenses" not in text


def test_dockerignore_excludes_the_venv_and_test_suite():
    text = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for entry in (".venv", ".git", "tests", "docs"):
        assert entry in text.splitlines()
