"""FR-CI-02 / FR-RPT-06: gate only on what is new since a previous scan, and say what changed."""

from __future__ import annotations

import json

import pytest

from websec_scanner import catalog
from websec_scanner.baseline import BaselineError, load_baseline
from websec_scanner.models import Finding, ScanResult, Severity
from websec_scanner.output import build_report, gate_message

TARGET = "https://t.example/"


def _finding(fid: str, severity: Severity, key: str, check: str = "security-headers") -> Finding:
    f = Finding(
        id=fid, title=f"title {fid}", severity=severity, owasp_category="A05:2021 - x",
        description="d", url=TARGET, instance_key=key,
    )  # fmt: skip
    from dataclasses import replace

    return replace(catalog.enrich(f, TARGET), check=check)


def _result(*findings: Finding, checks=("security-headers", "cors")) -> ScanResult:
    result = ScanResult(target=TARGET, started_at="2026-10-01T00:00:00Z", finished_at="2026-10-01T00:00:01Z")
    result.baseline_fetched = True
    result.checks_run = list(checks)
    for f in findings:
        result.add(f)
    return result


CSP = ("HDR-CONTENT-SECURITY-POLICY-MISSING", Severity.MEDIUM, "content-security-policy")
HSTS = ("HDR-STRICT-TRANSPORT-SECURITY-MISSING", Severity.HIGH, "strict-transport-security")
CORS = ("CORS-REFLECTS-ARBITRARY-ORIGIN", Severity.HIGH, TARGET, "cors")


@pytest.fixture
def baseline_file(tmp_path):
    """Write a report as a baseline file, the way a previous --json run would have."""

    def write(*findings: Finding, checks=("security-headers", "cors"), **overrides) -> str:
        report = build_report(_result(*findings, checks=checks))
        report.update(overrides)
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return str(path)

    return write


# --- loading -------------------------------------------------------------------


def test_a_previous_json_report_loads_as_a_baseline(baseline_file):
    baseline = load_baseline(baseline_file(_finding(*CSP)))
    assert len(baseline.fingerprints) == 1


@pytest.mark.parametrize(
    "content, message",
    [
        ("not json at all", "not valid JSON"),
        ("[]", "not a scan report"),
        ('{"findings": "nope"}', "not a scan report"),
        ('{"findings": [{"id": "X"}]}', "no fingerprint"),
        ('{"findings": [{"fingerprint": "short"}]}', "no fingerprint"),
    ],
)
def test_a_file_that_is_not_a_report_is_rejected_with_a_clear_message(tmp_path, content, message):
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(BaselineError, match=message):
        load_baseline(str(path))


def test_a_missing_baseline_file_is_a_clear_error(tmp_path):
    with pytest.raises(BaselineError, match="cannot read"):
        load_baseline(str(tmp_path / "nope.json"))


# --- the gate -----------------------------------------------------------------


def test_without_a_baseline_every_finding_counts_and_nothing_is_marked(baseline_file):
    report = build_report(_result(_finding(*HSTS)))
    assert report["findings"][0]["baseline_state"] is None
    assert report["baseline"] is None
    assert report["gate"]["failed"] is True
    assert report["gate"]["basis"] == "all"


def test_a_finding_already_in_the_baseline_does_not_fail_the_gate(baseline_file):
    old = load_baseline(baseline_file(_finding(*HSTS)))
    report = build_report(_result(_finding(*HSTS)), baseline=old)
    assert report["findings"][0]["baseline_state"] == "unchanged"
    assert report["gate"]["failed"] is False
    assert report["gate"]["basis"] == "new"


def test_a_new_finding_fails_the_gate_even_with_old_ones_present(baseline_file):
    old = load_baseline(baseline_file(_finding(*CSP)))
    report = build_report(_result(_finding(*CSP), _finding(*HSTS)), baseline=old)
    states = {f["id"]: f["baseline_state"] for f in report["findings"]}
    assert states == {
        "HDR-CONTENT-SECURITY-POLICY-MISSING": "unchanged",
        "HDR-STRICT-TRANSPORT-SECURITY-MISSING": "new",
    }
    assert report["gate"]["failed"] is True
    assert report["gate"]["counted"]["HIGH"] == 1 and report["gate"]["counted"]["MEDIUM"] == 0


def test_summary_still_counts_every_finding(baseline_file):
    # summary keeps its meaning (all findings), so nothing that reads it is silently wrong.
    old = load_baseline(baseline_file(_finding(*HSTS)))
    report = build_report(_result(_finding(*HSTS)), baseline=old)
    assert report["summary"]["HIGH"] == 1
    assert report["gate"]["counted"]["HIGH"] == 0


def test_the_gate_message_says_new_when_a_baseline_is_used(baseline_file):
    old = load_baseline(baseline_file(_finding(*CSP)))
    _, failing = gate_message(build_report(_result(_finding(*CSP), _finding(*HSTS)), baseline=old)["gate"])
    _, passing = gate_message(
        build_report(_result(_finding(*HSTS)), baseline=load_baseline(baseline_file(_finding(*HSTS))))["gate"]
    )
    assert "New findings" in failing
    assert "No new findings" in passing


# --- comparison (FR-RPT-06) ----------------------------------------------------


def test_a_finding_gone_since_the_baseline_is_reported_as_fixed(baseline_file):
    old = load_baseline(baseline_file(_finding(*CSP), _finding(*HSTS)))
    report = build_report(_result(_finding(*CSP)), baseline=old)
    fixed = report["baseline"]["fixed"]
    assert [f["id"] for f in fixed] == ["HDR-STRICT-TRANSPORT-SECURITY-MISSING"]
    assert report["baseline"]["counts"] == {"new": 0, "unchanged": 1, "fixed": 1, "not_rechecked": 0}


def test_a_finding_whose_check_did_not_run_is_not_called_fixed(baseline_file):
    # --checks headers this time: the old CORS finding was not looked at, so it is not "fixed".
    old = load_baseline(baseline_file(_finding(*CSP), _finding(*CORS)))
    report = build_report(_result(_finding(*CSP), checks=("security-headers",)), baseline=old)
    assert report["baseline"]["fixed"] == []
    assert [f["id"] for f in report["baseline"]["not_rechecked"]] == ["CORS-REFLECTS-ARBITRARY-ORIGIN"]


def test_nothing_is_called_fixed_when_the_scan_did_not_finish(baseline_file):
    # A scan stopped by --max-requests may simply not have reached the check again.
    old = load_baseline(baseline_file(_finding(*CSP), _finding(*HSTS)))
    result = _result(_finding(*CSP))
    result.limits = dict(result.limits, stopped_by="max-requests")
    report = build_report(result, baseline=old)
    assert report["baseline"]["fixed"] == []
    assert {f["id"] for f in report["baseline"]["not_rechecked"]} == {"HDR-STRICT-TRANSPORT-SECURITY-MISSING"}


def test_the_baseline_block_names_where_it_came_from(baseline_file):
    path = baseline_file(_finding(*CSP), scan_id="11111111-1111-4111-8111-111111111111")
    report = build_report(_result(_finding(*CSP)), baseline=load_baseline(path))
    assert report["baseline"]["scan_id"] == "11111111-1111-4111-8111-111111111111"
    assert report["baseline"]["started_at"] == "2026-10-01T00:00:00Z"


def test_a_secret_in_an_old_unredacted_baseline_is_not_copied_into_the_new_report(tmp_path):
    # A baseline written with --show-secrets may carry a raw token; the fixed list must not repeat it.
    report = build_report(_result(_finding(*HSTS)))
    report["findings"][0]["url"] = "https://t.example/?token=hunter2-secret"
    path = tmp_path / "b.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    new = build_report(_result(), baseline=load_baseline(str(path)))
    assert "hunter2-secret" not in json.dumps(new["baseline"])


def test_a_baseline_from_before_the_fingerprint_fix_triggers_a_warning(baseline_file):
    # FR-MODEL-07 changed CORS and redirect fingerprints for scans started off the site root.
    old = load_baseline(baseline_file(_finding(*CSP), scanner_version="1.13.0"))
    report = build_report(_result(_finding(*CSP)), baseline=old)
    assert any("regenerate" in e.lower() and "1.13.0" in e for e in report["errors"]), report["errors"]


def test_a_current_baseline_triggers_no_warning(baseline_file):
    old = load_baseline(baseline_file(_finding(*CSP)))
    report = build_report(_result(_finding(*CSP)), baseline=old)
    assert not any("regenerate" in e.lower() for e in report["errors"])
