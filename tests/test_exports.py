"""FR-RPT-03: CSV and JUnit XML exports, built from the same redacted report as every other format."""

from __future__ import annotations

import csv
import io
import json
import xml.etree.ElementTree as ET

import pytest
from mock_server import Handler as MockHandler

from websec_scanner import catalog, cli
from websec_scanner.exports import to_csv, to_junit
from websec_scanner.models import Finding, ScanResult, Severity
from websec_scanner.output import build_report, exit_code

TARGET = "https://t.example/"


def _finding(fid: str, severity: Severity, key: str, **fields) -> Finding:
    from dataclasses import replace

    f = Finding(id=fid, title=fields.pop("title", "t"), severity=severity, owasp_category="c",
                description=fields.pop("description", "d"), url=TARGET, instance_key=key, **fields)  # fmt: skip
    return replace(catalog.enrich(f, TARGET), check="security-headers")


def _report(*findings: Finding, fail_on: str = "high", fetched: bool = True) -> dict:
    result = ScanResult(target=TARGET, started_at="2026-10-01T00:00:00Z", finished_at="2026-10-01T00:00:05Z")
    result.baseline_fetched = fetched
    result.checks_run = ["security-headers"]
    for f in findings:
        result.add(f)
    return build_report(result, fail_on=fail_on)


HSTS = ("HDR-STRICT-TRANSPORT-SECURITY-MISSING", Severity.HIGH, "strict-transport-security")
CSP = ("HDR-CONTENT-SECURITY-POLICY-MISSING", Severity.MEDIUM, "content-security-policy")


# --- CSV -----------------------------------------------------------------------


def _rows(text: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(text)))


def test_csv_has_one_row_per_finding_with_the_key_columns():
    rows = _rows(to_csv(_report(_finding(*HSTS), _finding(*CSP))))
    assert [r["id"] for r in rows] == ["HDR-STRICT-TRANSPORT-SECURITY-MISSING", "HDR-CONTENT-SECURITY-POLICY-MISSING"]
    assert {"severity", "id", "title", "url", "fingerprint", "counts_toward_gate", "baseline_state"} <= set(rows[0])


def test_csv_marks_what_counts_toward_the_gate():
    rows = {r["id"]: r for r in _rows(to_csv(_report(_finding(*HSTS), _finding(*CSP))))}
    assert rows["HDR-STRICT-TRANSPORT-SECURITY-MISSING"]["counts_toward_gate"] == "yes"
    assert rows["HDR-CONTENT-SECURITY-POLICY-MISSING"]["counts_toward_gate"] == "yes"


@pytest.mark.parametrize("payload", ['=HYPERLINK("http://evil")', "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"])
def test_csv_neutralises_spreadsheet_formulas_from_the_target(payload):
    # The title and description quote what the target sent (a cookie name, a header value);
    # a cell starting with = + - @ would run as a formula when opened in a spreadsheet.
    report = _report(_finding(*HSTS, title=payload, description=payload))
    (row,) = _rows(to_csv(report))
    assert row["title"].startswith("'") and row["description"].startswith("'")
    assert row["title"][1:] == payload


def test_csv_leaves_ordinary_values_alone():
    (row,) = _rows(to_csv(_report(_finding(*HSTS, title="Missing header"))))
    assert row["title"] == "Missing header"


def test_csv_of_a_clean_scan_still_has_a_header_row():
    text = to_csv(_report())
    assert text.splitlines()[0].startswith("severity,")
    assert _rows(text) == []


# --- JUnit ---------------------------------------------------------------------


def _suite(xml: str) -> ET.Element:
    root = ET.fromstring(xml)  # noqa: S314 - parses the scanner's own output; production code never reads XML
    assert root.tag == "testsuites"
    (suite,) = root.findall("testsuite")
    return suite


def test_junit_is_well_formed_and_counts_add_up():
    suite = _suite(to_junit(_report(_finding(*HSTS), _finding(*CSP))))
    cases = suite.findall("testcase")
    assert int(suite.get("tests")) == len(cases)
    assert int(suite.get("failures")) == len([c for c in cases if c.find("failure") is not None])
    assert int(suite.get("skipped")) == len([c for c in cases if c.find("skipped") is not None])


def test_junit_fails_only_what_fails_the_gate():
    # --fail-on high: the HIGH finding fails, the MEDIUM one is reported but skipped.
    suite = _suite(to_junit(_report(_finding(*HSTS), _finding(*CSP))))
    by_name = {c.get("name"): c for c in suite.findall("testcase")}
    hsts = next(c for n, c in by_name.items() if "HDR-STRICT-TRANSPORT-SECURITY-MISSING" in n)
    csp = next(c for n, c in by_name.items() if "HDR-CONTENT-SECURITY-POLICY-MISSING" in n)
    assert hsts.find("failure") is not None
    assert "below the --fail-on high threshold" in csp.find("skipped").get("message")


@pytest.mark.parametrize(
    "findings, fail_on, fetched",
    [
        ((HSTS, CSP), "high", True),  # fails: HIGH present
        ((CSP,), "high", True),  # passes: only MEDIUM
        ((CSP,), "medium", True),  # fails: MEDIUM at the threshold
        ((), "high", True),  # clean
        ((), "high", False),  # incomplete: exit 3
        ((HSTS,), "none", False),  # --fail-on none: never fails, even incomplete
    ],
)
def test_junit_fails_exactly_when_the_cli_exits_non_zero(findings, fail_on, fetched):
    # A CI dashboard reading the JUnit file must reach the same verdict as the exit code.
    report = _report(*(_finding(*f) for f in findings), fail_on=fail_on, fetched=fetched)
    suite = _suite(to_junit(report))
    assert (int(suite.get("failures")) > 0) == (exit_code(report) != 0)


def test_junit_of_a_clean_scan_still_reports_one_test():
    # Some CI systems treat a JUnit file with zero tests as an error.
    suite = _suite(to_junit(_report()))
    assert int(suite.get("tests")) >= 1 and int(suite.get("failures")) == 0


def test_junit_escapes_markup_from_the_target():
    report = _report(_finding(*HSTS, title='<x a="1">&</x>', description="]]> <script>"))
    xml = to_junit(report)
    case = next(c for c in _suite(xml).findall("testcase") if "HDR-STRICT" in c.get("name"))
    assert '<x a="1">&</x>' in case.get("name") or '<x a="1">&</x>' in case.find("failure").get("message")


def test_junit_drops_characters_xml_cannot_carry():
    # A control character in a header value would make the whole file unparseable.
    report = _report(_finding(*HSTS, description="bad\x00\x08\x1bchars"))
    ET.fromstring(to_junit(report))  # noqa: S314 - must not raise; parses the scanner's own output


# --- through the CLI -----------------------------------------------------------


def test_cli_writes_csv_and_junit_from_the_redacted_report(http_server, tmp_path):
    csv_path, junit_path, json_path = tmp_path / "r.csv", tmp_path / "r.xml", tmp_path / "r.json"
    cli.main([http_server(MockHandler), "--yes", "--no-color",
              "--csv", str(csv_path), "--junit", str(junit_path), "--json", str(json_path)])  # fmt: skip
    report = json.loads(json_path.read_text(encoding="utf-8"))
    rows = _rows(csv_path.read_text(encoding="utf-8"))
    assert len(rows) == len(report["findings"])
    suite = _suite(junit_path.read_text(encoding="utf-8"))
    assert int(suite.get("failures")) > 0  # the mock server has HIGH findings
    for text in (csv_path.read_text(encoding="utf-8"), junit_path.read_text(encoding="utf-8")):
        assert "abc123" not in text and "hunter2" not in text  # the mock server's fake secrets
