"""FR-CI-02 / FR-RPT-06 / FR-MODEL-06 in the human-readable views: console and HTML."""

from __future__ import annotations

import datetime
import io
import json
from contextlib import redirect_stdout
from dataclasses import replace

import pytest

from websec_scanner import catalog
from websec_scanner.baseline import load_baseline
from websec_scanner.html_report import render_html
from websec_scanner.models import Finding, ScanResult, Severity
from websec_scanner.output import build_report
from websec_scanner.report import print_report
from websec_scanner.suppressions import load_suppressions

TARGET = "https://t.example/"


def _finding(fid: str, severity: Severity, key: str) -> Finding:
    f = Finding(id=fid, title=f"title of {fid}", severity=severity, owasp_category="c", description="d",
                url=TARGET, instance_key=key)  # fmt: skip
    return replace(catalog.enrich(f, TARGET), check="security-headers")


def _result(*findings: Finding) -> ScanResult:
    r = ScanResult(target=TARGET, started_at="2026-10-01T00:00:00Z", finished_at="2026-10-01T00:00:01Z")
    r.baseline_fetched = True
    r.checks_run = ["security-headers"]
    for f in findings:
        r.add(f)
    return r


OLD = _finding("HDR-OLD-MISSING", Severity.HIGH, "old")
NEW = _finding("HDR-NEW-MISSING", Severity.HIGH, "new")
GONE = _finding("HDR-GONE-MISSING", Severity.MEDIUM, "gone")
OK = _finding("HDR-OK-MISSING", Severity.HIGH, "ok")


@pytest.fixture
def compared(tmp_path):
    base = tmp_path / "b.json"
    base.write_text(json.dumps(build_report(_result(OLD, GONE))), encoding="utf-8")
    ignore = tmp_path / "i.toml"
    ignore.write_text(
        '[[suppress]]\nid = "HDR-OK-MISSING"\nreason = "Fixed upstream"\nexpires = 2026-12-31\n', encoding="utf-8"
    )
    return build_report(
        _result(OLD, NEW, OK),
        baseline=load_baseline(str(base)),
        suppressions=load_suppressions(str(ignore), today=datetime.date(2026, 10, 1)),
    )


def _console(report: dict) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        print_report(report, use_color=False)
    return buffer.getvalue()


def test_console_marks_each_finding_and_lists_what_was_fixed(compared):
    out = _console(compared)
    assert "[NEW]" in out and "[UNCHANGED]" in out
    assert "[SUPPRESSED until 2026-12-31: Fixed upstream]" in out
    assert "Compared with baseline" in out
    assert "Fixed since the baseline" in out and "title of HDR-GONE-MISSING" in out


def test_console_shows_what_counts_toward_the_gate(compared):
    out = _console(compared)
    # Three HIGH findings exist, but only the new, unsuppressed one counts.
    assert "Counted toward the gate: CRITICAL: 0 | HIGH: 1 |" in out


def test_console_without_a_baseline_is_unchanged():
    out = _console(build_report(_result(OLD)))
    assert "[NEW]" not in out and "Compared with baseline" not in out and "Counted toward the gate" not in out


def test_html_marks_each_finding(compared):
    html = render_html(compared)
    # NEW and OK are both absent from the baseline, so both are new; OK is also suppressed.
    assert html.count('class="state new"') == 2
    assert html.count('class="state unchanged"') == 1
    assert html.count('class="state suppressed"') == 1 and "Fixed upstream" in html


def test_html_has_a_comparison_section_with_the_fixed_findings(compared):
    html = render_html(compared)
    assert "Compared with baseline" in html
    assert "title of HDR-GONE-MISSING" in html
    assert "<td>1</td>" in html  # one new, one unchanged, one fixed


def test_html_without_a_baseline_has_no_comparison_section():
    html = render_html(build_report(_result(OLD)))
    assert "Compared with baseline" not in html and 'class="state' not in html


def test_html_escapes_a_suppression_reason():
    # The reason is the operator's text, but it still goes into HTML: escape it.
    report = build_report(_result(OLD))
    report["findings"][0]["suppression"] = {"reason": "<script>alert(1)</script>", "expires": "2026-12-31"}
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
