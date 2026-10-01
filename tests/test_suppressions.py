"""FR-MODEL-06: accept a known finding on purpose, with a reason and an end date."""

from __future__ import annotations

import datetime

import pytest

from websec_scanner import catalog
from websec_scanner.models import Finding, ScanResult, Severity
from websec_scanner.output import build_report
from websec_scanner.suppressions import SuppressionError, load_suppressions

TARGET = "https://t.example/"
TODAY = datetime.date(2026, 10, 1)


def _finding(fid: str, severity: Severity, key: str, url: str = TARGET) -> Finding:
    from dataclasses import replace

    f = Finding(id=fid, title="t", severity=severity, owasp_category="c", description="d", url=url, instance_key=key)
    return replace(catalog.enrich(f, TARGET), check="security-headers")


def _result(*findings: Finding) -> ScanResult:
    result = ScanResult(target=TARGET, started_at="2026-10-01T00:00:00Z")
    result.baseline_fetched = True
    result.checks_run = ["security-headers"]
    for f in findings:
        result.add(f)
    return result


HSTS = _finding("HDR-STRICT-TRANSPORT-SECURITY-MISSING", Severity.HIGH, "strict-transport-security")
CSP = _finding("HDR-CONTENT-SECURITY-POLICY-MISSING", Severity.MEDIUM, "content-security-policy")
ENV = _finding("EXPOSURE-ENV", Severity.CRITICAL, ".env", url="https://t.example/legacy/.env")


@pytest.fixture
def toml(tmp_path):
    def write(text: str) -> str:
        path = tmp_path / ".scannerignore.toml"
        path.write_text(text, encoding="utf-8")
        return str(path)

    return write


# --- matching ------------------------------------------------------------------


def test_a_suppressed_finding_does_not_fail_the_gate_but_is_still_listed(toml):
    text = (
        "[[suppress]]\n"
        'id = "HDR-STRICT-TRANSPORT-SECURITY-MISSING"\n'
        'reason = "HSTS set at the CDN"\n'
        "expires = 2026-12-31\n"
    )
    rules = load_suppressions(toml(text), today=TODAY)
    report = build_report(_result(HSTS), suppressions=rules)
    (finding,) = report["findings"]
    assert finding["suppression"] == {"reason": "HSTS set at the CDN", "expires": "2026-12-31"}
    assert report["gate"]["failed"] is False
    assert report["summary"]["HIGH"] == 1  # still counted as a finding, just not toward the gate


def test_match_by_fingerprint(toml):
    rules = load_suppressions(
        toml(f'[[suppress]]\nfingerprint = "{HSTS.fingerprint}"\nreason = "r"\nexpires = 2026-12-31\n'), today=TODAY
    )
    report = build_report(_result(HSTS, CSP), suppressions=rules)
    assert {f["id"]: f["suppression"] is not None for f in report["findings"]} == {
        "HDR-STRICT-TRANSPORT-SECURITY-MISSING": True,
        "HDR-CONTENT-SECURITY-POLICY-MISSING": False,
    }


def test_match_by_path_glob(toml):
    rules = load_suppressions(
        toml('[[suppress]]\npath = "/legacy/*"\nreason = "r"\nexpires = 2026-12-31\n'), today=TODAY
    )
    report = build_report(_result(ENV, HSTS), suppressions=rules)
    assert [f["id"] for f in report["findings"] if f["suppression"]] == ["EXPOSURE-ENV"]


def test_every_field_given_must_match(toml):
    # id AND path: an .env finding elsewhere on the site is not covered.
    rules = load_suppressions(
        toml('[[suppress]]\nid = "EXPOSURE-ENV"\npath = "/other/*"\nreason = "r"\nexpires = 2026-12-31\n'), today=TODAY
    )
    report = build_report(_result(ENV), suppressions=rules)
    assert report["findings"][0]["suppression"] is None


# --- expiry ----------------------------------------------------------------------


def test_an_expired_suppression_stops_suppressing_and_says_so(toml):
    rules = load_suppressions(
        toml('[[suppress]]\nid = "HDR-STRICT-TRANSPORT-SECURITY-MISSING"\nreason = "r"\nexpires = 2026-09-30\n'),
        today=TODAY,
    )
    report = build_report(_result(HSTS), suppressions=rules)
    assert report["findings"][0]["suppression"] is None
    assert report["gate"]["failed"] is True
    assert any("expired on 2026-09-30" in e for e in report["errors"]), report["errors"]


def test_a_suppression_is_still_valid_on_its_expiry_date(toml):
    rules = load_suppressions(
        toml('[[suppress]]\nid = "HDR-STRICT-TRANSPORT-SECURITY-MISSING"\nreason = "r"\nexpires = 2026-10-01\n'),
        today=TODAY,
    )
    assert build_report(_result(HSTS), suppressions=rules)["findings"][0]["suppression"] is not None


def test_a_quoted_date_is_accepted_too(toml):
    rules = load_suppressions(
        toml('[[suppress]]\nid = "HDR-STRICT-TRANSPORT-SECURITY-MISSING"\nreason = "r"\nexpires = "2026-12-31"\n'),
        today=TODAY,
    )
    assert build_report(_result(HSTS), suppressions=rules)["findings"][0]["suppression"] is not None


# --- validation: a typo must never quietly widen a suppression -----------------


@pytest.mark.parametrize(
    "body, message",
    [
        ('id = "X"\nexpires = 2026-12-31\n', "reason"),
        ('id = "X"\nreason = "  "\nexpires = 2026-12-31\n', "reason"),
        ('id = "X"\nreason = "r"\n', "expires"),
        ('id = "X"\nreason = "r"\nexpires = "next year"\n', "expires"),
        ('reason = "r"\nexpires = 2026-12-31\n', "at least one of"),  # would match everything
        ('id = "X"\nreason = "r"\nexpires = 2026-12-31\nreasn = "typo"\n', "unknown key"),
        ('fingerprint = "zz"\nreason = "r"\nexpires = 2026-12-31\n', "fingerprint"),
    ],
)
def test_an_invalid_entry_rejects_the_whole_file(toml, body, message):
    with pytest.raises(SuppressionError, match=message):
        load_suppressions(toml("[[suppress]]\n" + body), today=TODAY)


def test_a_file_that_is_not_toml_is_rejected(toml):
    with pytest.raises(SuppressionError, match="not valid TOML"):
        load_suppressions(toml("this is = = not toml"), today=TODAY)


def test_a_missing_file_is_a_clear_error(tmp_path):
    with pytest.raises(SuppressionError, match="cannot read"):
        load_suppressions(str(tmp_path / "missing.toml"), today=TODAY)


def test_an_empty_file_suppresses_nothing(toml):
    rules = load_suppressions(toml("# nothing accepted yet\n"), today=TODAY)
    assert build_report(_result(HSTS), suppressions=rules)["gate"]["failed"] is True


# --- interaction with a baseline -----------------------------------------------


def test_a_suppressed_new_finding_does_not_fail_the_gate_either(toml, tmp_path):
    import json

    from websec_scanner.baseline import load_baseline

    path = tmp_path / "b.json"
    path.write_text(json.dumps(build_report(_result(CSP))), encoding="utf-8")
    rules = load_suppressions(
        toml('[[suppress]]\nid = "HDR-STRICT-TRANSPORT-SECURITY-MISSING"\nreason = "r"\nexpires = 2026-12-31\n'),
        today=TODAY,
    )
    report = build_report(_result(CSP, HSTS), baseline=load_baseline(str(path)), suppressions=rules)
    hsts = next(f for f in report["findings"] if f["id"] == "HDR-STRICT-TRANSPORT-SECURITY-MISSING")
    assert hsts["baseline_state"] == "new" and hsts["suppression"] is not None
    assert report["gate"]["failed"] is False
