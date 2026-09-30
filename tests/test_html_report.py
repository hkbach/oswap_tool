"""Tests for the standalone HTML report (owasp_scanner.html_report)."""
from __future__ import annotations

from mock_server import Handler as MockHandler

from owasp_scanner import cli
from owasp_scanner.html_report import render_html


def _report(**overrides):
    report = {
        "target": "https://t.example/",
        "started_at": "2026-09-30T01:00:00.000000Z",
        "finished_at": "2026-09-30T01:00:05.000000Z",
        "checks_run": ["security-headers", "cookies"],
        "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 1},
        "findings": [
            {"id": "HDR-INFO-SERVER", "title": "Server header", "severity": "INFO",
             "owasp_category": "A05:2021 - Security Misconfiguration", "description": "d",
             "evidence": "server: x", "recommendation": "", "url": ""},
            {"id": "HDR-CONTENT-SECURITY-POLICY-MISSING", "title": "Missing CSP", "severity": "MEDIUM",
             "owasp_category": "A05:2021 - Security Misconfiguration", "description": "d",
             "evidence": "", "recommendation": "Add a CSP", "url": "https://t.example/"},
        ],
        "errors": [],
    }
    report.update(overrides)
    return report


def test_report_is_standalone_english_html():
    html = render_html(_report())
    assert html.startswith("<!doctype html>") and '<html lang="en">' in html
    assert "OWASP Passive Scan Report" in html and "https://t.example/" in html
    assert "<script" not in html and "http://" not in html.replace("https://t.example/", "")
    assert "No CRITICAL/HIGH findings" in html


def test_findings_sorted_by_severity():
    html = render_html(_report())
    assert html.index("Missing CSP") < html.index("Server header")


def test_values_from_target_are_escaped():
    hostile = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    report = _report(
        target='https://t.example/"><script>',
        errors=[hostile],
        findings=[{"id": hostile, "title": hostile, "severity": "HIGH", "owasp_category": hostile,
                   "description": hostile, "evidence": hostile, "recommendation": hostile, "url": hostile}],
        summary={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    )
    html = render_html(report)
    assert "<script" not in html and "<img" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "fails the CI gate" in html


def test_unknown_severity_does_not_break_rendering():
    report = _report(findings=[{"id": "X", "title": "odd", "severity": "WEIRD", "description": ""}])
    assert "odd" in render_html(report)


def test_errors_and_empty_findings():
    html = render_html(_report(findings=[], errors=["Could not fetch https://t.example/: boom"],
                               summary={s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}))
    assert "Non-fatal errors during scan" in html and "No findings." in html
    assert "could not be fetched" in html


def test_renders_a_real_scan(http_server):
    report = cli.run_scan(http_server(MockHandler)).to_dict()
    html = render_html(report)
    for finding in report["findings"]:
        assert finding["id"] in html
