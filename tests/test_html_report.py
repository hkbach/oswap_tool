"""Tests for the standalone HTML report (owasp_scanner.html_report)."""

from __future__ import annotations

from mock_server import Handler as MockHandler

from owasp_scanner import catalog, cli, output
from owasp_scanner.html_report import render_html


def _report(**overrides):
    report = {
        "target": "https://t.example/",
        "started_at": "2026-09-30T01:00:00.000000Z",
        "finished_at": "2026-09-30T01:00:05.000000Z",
        "scan_groups": list(catalog.GROUP_IDS),
        "checks_run": ["security-headers", "cookies"],
        "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 1},
        "findings": [
            {
                "id": "HDR-INFO-SERVER",
                "title": "Server header",
                "severity": "INFO",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "description": "d",
                "evidence": "server: x",
                "recommendation": "",
                "url": "",
            },
            {
                "id": "HDR-CONTENT-SECURITY-POLICY-MISSING",
                "title": "Missing CSP",
                "severity": "MEDIUM",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "description": "d",
                "evidence": "",
                "recommendation": "Add a CSP",
                "url": "https://t.example/",
            },
        ],
        "errors": [],
        "gate": {"fail_on": "high", "failed": False, "incomplete": False},
    }
    report.update(overrides)
    for finding in report["findings"]:  # build_report() output always names the producing check
        finding.setdefault("check", "security-headers")
    return report


def test_report_is_standalone_english_html():
    html = render_html(_report())
    assert html.startswith("<!doctype html>") and '<html lang="en">' in html
    assert "OWASP Non-intrusive Scan Report" in html and "https://t.example/" in html
    assert "<script" not in html and "http://" not in html.replace("https://t.example/", "")
    assert "No findings at or above the --fail-on high threshold" in html


def test_findings_sorted_by_severity():
    html = render_html(_report())
    assert html.index("Missing CSP") < html.index("Server header")


def test_values_from_target_are_escaped():
    hostile = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    report = _report(
        target='https://t.example/"><script>',
        errors=[hostile],
        findings=[
            {
                "id": hostile,
                "title": hostile,
                "severity": "HIGH",
                "owasp_category": hostile,
                "description": hostile,
                "evidence": hostile,
                "recommendation": hostile,
                "url": hostile,
            }
        ],
        summary={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        gate={"fail_on": "high", "failed": True, "incomplete": False},
    )
    html = render_html(report)
    assert "<script" not in html and "<img" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "fails the CI gate" in html


def test_unknown_severity_does_not_break_rendering():
    report = _report(findings=[{"id": "X", "title": "odd", "severity": "WEIRD", "description": ""}])
    assert "odd" in render_html(report)


def test_errors_and_empty_findings():
    html = render_html(
        _report(
            findings=[],
            errors=["Could not fetch https://t.example/: boom"],
            summary={s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
            gate={"fail_on": "high", "failed": False, "incomplete": True},
        )
    )
    assert "Non-fatal errors during scan" in html and "No findings." in html
    assert "could not be fetched" in html


def test_renders_a_real_scan(http_server):
    report = output.build_report(cli.run_scan(http_server(MockHandler)))
    html = render_html(report)
    for finding in report["findings"]:
        assert finding["id"] in html


def test_classification_and_only_https_references_are_rendered():
    finding = {
        "id": "HDR-CSP-UNSAFE",
        "title": "t",
        "severity": "MEDIUM",
        "owasp_category": "A03:2021 - Injection",
        "cwe": "CWE-693",
        "confidence": "high",
        "description": "d",
        "references": ["https://owasp.org/x", "javascript:alert(1)"],
    }
    html = render_html(_report(findings=[finding]))
    assert "CWE-693" in html and "confidence high" in html
    assert '<a href="https://owasp.org/x">' in html
    assert "javascript:" not in html


def test_report_groups_findings_by_test_target_and_summarises_owasp():
    html = render_html(_report(scan_groups=["headers", "cookies", "tls"]))
    for title in ("Summary by test target", "Summary by OWASP Top 10", "Findings by test target"):
        assert title in html
    # every group has a section; unselected ones say so and are listed as not tested
    for group in catalog.CHECK_GROUPS:
        assert f'id="group-{group.id}"' in html
    assert '<span class="status issues">2 issues</span>' in html
    assert '<span class="status clean">No issues</span>' in html  # cookies ran, nothing found
    assert '<span class="status not-run">Not run</span>' in html  # tls selected, did not run
    assert "<tr><th>Not selected (not tested)</th><td>HTTP to HTTPS redirect, CORS" in html
    # the OWASP table links to findings that exist in the page
    assert '<a href="#finding-0">HDR-INFO-SERVER</a>' in html and 'id="finding-0"' in html
    assert html.index("Missing CSP") < html.index("Server header")  # severity order inside a group


def test_full_scan_report_has_no_not_selected_row():
    assert "Not selected (not tested)" not in render_html(_report())
