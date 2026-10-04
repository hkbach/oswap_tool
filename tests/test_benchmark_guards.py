"""FR-QA-03a/03b/03d: guards on the benchmark's checked-in files.

The benchmark apps only run in CI (Docker), so these offline checks are what keeps the
compose file, the workflow and the ground truth honest on a developer machine: every image
pinned by digest, every port on loopback, every expected file consistent with the compose file.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from benchmarks import scoring

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"
COMPOSE = BENCH / "docker-compose.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "benchmark.yml"
EXPECTED = sorted((BENCH / "expected").glob("*.toml"))

# D6: Juice Shop and VAmPI now; badssl.com waits for the TLS probing package (D7).
APPS = {"juice-shop", "vampi"}


def compose_text() -> str:
    return COMPOSE.read_text(encoding="utf-8")


def published_ports(text: str) -> dict[str, list[str]]:
    """service -> the entries under its ``ports:`` key (the compose file is kept in a plain shape)."""
    ports: dict[str, list[str]] = {}
    service, in_ports, ports_indent = None, False, 0
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip())
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            service, in_ports = match.group(1), False
            continue
        stripped = line.strip()
        if stripped == "ports:":
            in_ports, ports_indent = True, indent
            ports.setdefault(service, [])
        elif in_ports and stripped.startswith("- "):
            ports[service].append(stripped[2:].strip().strip("\"'"))
        elif in_ports and stripped and indent <= ports_indent:
            in_ports = False
    return ports


# --- compose ---------------------------------------------------------------------------------


def test_the_compose_file_has_exactly_the_decided_apps():
    assert set(scoring.compose_images(compose_text())) == APPS


@pytest.mark.parametrize("service, image", sorted(scoring.compose_images(compose_text()).items()))
def test_every_image_is_pinned_by_digest_not_by_tag(service, image):
    assert re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", image), f"{service}: {image}"


def test_every_published_port_is_bound_to_loopback_only():
    ports = published_ports(compose_text())
    assert set(ports) == APPS and all(ports.values()), "each app must publish its port, on 127.0.0.1"
    for service, entries in ports.items():
        for entry in entries:
            assert entry.startswith("127.0.0.1:"), f"{service} publishes {entry!r} beyond loopback"


ALL_INTERFACES = "0.0.0" + ".0"  # spelled in two parts: this is the address the compose file must never bind
FORBIDDEN_IN_COMPOSE = ["privileged", "network_mode", "cap_add", "pid:", "/var/run/docker.sock", ALL_INTERFACES]


@pytest.mark.parametrize("forbidden", FORBIDDEN_IN_COMPOSE)
def test_the_compose_file_asks_for_no_extra_privileges(forbidden):
    # Comments may warn about these words; only the configuration itself is checked.
    lines = [line.split("#", 1)[0] for line in compose_text().splitlines()]
    assert forbidden not in " ".join(lines)


def test_vampi_runs_in_its_vulnerable_mode():
    assert re.search(r'vulnerable:\s*"?1"?', compose_text())


# --- ground truth files -------------------------------------------------------------------------


def test_there_is_an_expected_file_for_every_app():
    assert {p.stem for p in EXPECTED} == APPS


@pytest.mark.parametrize("path", EXPECTED, ids=lambda p: p.stem)
def test_an_expected_file_is_valid_and_matches_the_compose_file(path):
    truth = scoring.load_ground_truth(path)
    assert truth.app == path.stem
    scoring.check_image_matches_compose(truth, scoring.compose_images(compose_text()))
    host_ports = {entry.split(":")[1] for entry in published_ports(compose_text())[truth.app]}
    assert str(re.search(r":(\d+)/?$", truth.target.rstrip("/") + "/").group(1)) in host_ports


def test_a_reviewed_ground_truth_always_comes_with_its_baseline():
    reviewed = [scoring.load_ground_truth(p) for p in EXPECTED if scoring.load_ground_truth(p).reviewed]
    if not reviewed:
        pytest.skip("no ground truth has been reviewed yet, so there is nothing to compare against")
    baseline = scoring.load_baseline(BENCH / "baseline.json")
    for truth in reviewed:
        assert truth.app in baseline["apps"], f"{truth.app} is reviewed but has no baseline"
        assert baseline["apps"][truth.app]["image"] == truth.image


def test_the_baseline_if_present_is_well_formed():
    path = BENCH / "baseline.json"
    if not path.exists():
        pytest.skip("no baseline recorded yet")
    assert set(scoring.load_baseline(path)["apps"]) <= APPS


# --- workflow ---------------------------------------------------------------------------------


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_the_workflow_runs_weekly_on_demand_and_when_the_scanner_changes():
    text = workflow_text()
    assert re.search(r"schedule:\s*\n\s*- cron:", text)
    assert "workflow_dispatch:" in text
    triggers = text[text.index("\non:") : text.index("\njobs:")]
    pull_request = triggers[triggers.index("pull_request:") :]
    assert "schedule:" not in pull_request, "keep pull_request last in the on: block so this check is exact"
    for path in ("websec_scanner/**", "benchmarks/**", ".github/workflows/benchmark.yml"):
        assert f'- "{path}"' in pull_request, path


def test_the_workflow_has_least_privilege_and_no_secrets():
    text = workflow_text()
    assert re.search(r"permissions:\s*\n\s+contents: read", text)
    assert "secrets." not in text
    assert "timeout-minutes:" in text, "a hung app must not hold a runner for hours"


def test_the_apps_are_always_shut_down_and_the_results_always_kept():
    text = workflow_text()
    assert re.search(r"if: always\(\)\s*\n\s+run: docker compose .*down", text)
    assert re.search(r"if: always\(\)\s*\n\s+uses: actions/upload-artifact@v\d+", text)


@pytest.mark.parametrize("path", EXPECTED, ids=lambda p: p.stem)
def test_the_workflow_waits_for_every_app_it_is_going_to_scan(path):
    # The readiness loop names the URLs by hand: if a target moves, the job would scan an app that
    # may not be up yet and report it as a data problem.
    assert scoring.load_ground_truth(path).target in workflow_text()


def test_a_manual_run_defaults_to_auto():
    text = workflow_text()
    assert "options: [auto, score, capture, update-baseline]" in text and "default: auto" in text


def test_the_workflow_runs_the_benchmark_and_publishes_the_table():
    text = workflow_text()
    assert "python -m benchmarks.run" in text
    assert "GITHUB_STEP_SUMMARY" in text


# --- packaging and hygiene -----------------------------------------------------------------------


def test_benchmarks_are_not_shipped_in_the_package():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["setuptools"]["packages"]["find"]["include"] == ["websec_scanner*"]


def test_per_run_results_are_not_committed():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "benchmarks/results/" in ignored


def test_the_readme_states_licenses_scope_and_what_the_numbers_are_not():
    text = (BENCH / "README.md").read_text(encoding="utf-8")
    for needle in ("Juice Shop", "VAmPI", "MIT", "127.0.0.1", "digest"):
        assert needle in text, needle
    assert "100%" not in text
    assert "not a detection rate" in text.lower()
