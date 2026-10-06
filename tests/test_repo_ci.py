"""FR-QA-07: the repository CI workflow runs the checks the backlog asks for.

The workflow is not executed here (it only runs on GitHub); these tests keep its
content consistent with the project configuration.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


@pytest.fixture(scope="module")
def workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_workflow_has_the_seven_jobs(workflow):
    jobs = set(re.findall(r"^  ([a-z-]+):$", workflow, flags=re.MULTILINE))
    assert {"lint", "test", "min-deps", "docker", "docker-publish", "audit", "secrets"} <= jobs


def test_docker_publish_job_only_runs_on_a_release_tag_after_the_smoke_test(workflow):
    job = workflow[workflow.index("  docker-publish:") : workflow.index("  secrets:")]
    assert "needs: docker" in job
    assert "startsWith(github.ref, 'refs/tags/v')" in job
    assert "ghcr.io/hkbach/websec-scanner" in job
    assert "github.ref_name" in job and ":latest" in job


def test_docker_job_builds_runs_non_root_and_smoke_tests_a_scan(workflow):
    job = workflow[workflow.index("  docker:") : workflow.index("  docker-publish:")]
    assert "docker build -t websec-scanner:ci ." in job
    assert "--help" in job and "--list-checks" in job
    assert "--entrypoint id" in job and 'uid" -ne 0' in job  # must not run as root
    assert "tests/mock_server.py" in job and "--network host" in job
    assert "ubuntu-24.04" in job  # Linux only: needs a Docker daemon


def test_min_deps_job_pins_the_floors_declared_in_pyproject(workflow):
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    runtime = re.search(r"^dependencies = \[(.*?)^\]", pyproject, flags=re.MULTILINE | re.DOTALL).group(1)
    floors = dict(re.findall(r'"([a-z0-9-]+)>=([\d.]+)"', runtime))
    assert floors and set(floors) == {"requests", "urllib3", "cryptography", "pyyaml"}
    job = workflow[workflow.index("  min-deps:") : workflow.index("  audit:")]
    for name, version in floors.items():
        assert f'"{name}=={version}"' in job, f"min-deps must install {name}=={version}"
    oldest = re.search(r'requires-python = ">=(\d+\.\d+)"', pyproject).group(1)
    assert f'python-version: "{oldest}"' in job
    # the service extra (decision D12) has floors too, and the same job proves them
    service = re.search(r"^service = \[(.*?)^\]", pyproject, flags=re.MULTILINE | re.DOTALL).group(1)
    service_floors = dict(re.findall(r'"([a-z0-9-]+)>=([\d.]+)"', service))
    assert service_floors and set(service_floors) == {"fastapi", "uvicorn"}
    for name, version in service_floors.items():
        assert f'"{name}=={version}"' in job, f"min-deps must install {name}=={version}"


def test_workflow_runs_lint_and_offline_tests(workflow):
    assert "ruff check ." in workflow
    assert "ruff format --check ." in workflow
    assert "python -m pytest" in workflow


def test_workflow_tests_oldest_supported_and_latest_python(workflow):
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    oldest = re.search(r'requires-python = ">=(\d+\.\d+)"', pyproject).group(1)
    pythons = set(re.findall(r'python: "(\d+\.\d+)"', workflow))
    assert oldest in pythons
    assert max(pythons, key=lambda v: tuple(map(int, v.split(".")))) != oldest
    assert "windows-latest" in workflow


def test_workflow_audits_dependencies_and_scans_for_secrets(workflow):
    assert "pip_audit" in workflow
    assert "gitleaks git . --config .gitleaks.toml" in workflow
    assert "sha256sum -c" in workflow
    assert "fetch-depth: 0" in workflow


def test_workflow_is_read_only_and_uses_no_repository_secrets(workflow):
    # Workflow-level default stays read-only; only the docker-publish job (tag pushes only)
    # is granted packages: write, scoped to that one job, to push the image to ghcr.io.
    assert re.search(r"^permissions:\n  contents: read$", workflow, flags=re.MULTILINE)
    publish_job = workflow[workflow.index("  docker-publish:") : workflow.index("  secrets:")]
    assert "packages: write" in publish_job
    assert "write" not in workflow.replace(publish_job, "")
    # secrets.GITHUB_TOKEN is this run's own ephemeral token (no repository secret to
    # configure); no other secrets.* reference is allowed anywhere in the workflow.
    for match in re.findall(r"secrets\.[A-Za-z0-9_]+", workflow):
        assert match == "secrets.GITHUB_TOKEN", f"unexpected repository secret referenced: {match}"


def test_workflow_has_no_tabs(workflow):
    assert "\t" not in workflow


def test_gitleaks_allowlist_only_covers_the_fake_redaction_values():
    config = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    assert "useDefault = true" in config
    assert re.findall(r"paths = \[(.*)\]", config) == [r"'''^tests/test_redact\.py$'''"]
    source = (ROOT / "tests" / "test_redact.py").read_text(encoding="utf-8")
    for value in re.findall(r"'''\^(.+?)\$'''", re.search(r"regexes = \[(.*)\]", config).group(1)):
        assert f'"{value}"' in source, f"{value} is not a fixture value in tests/test_redact.py"


def test_the_audit_job_covers_the_service_dependencies_too(workflow):
    job = workflow[workflow.index("  audit:") : workflow.index("  docker:")]
    assert 'pip install ".[service]"' in job and "--path" in job
