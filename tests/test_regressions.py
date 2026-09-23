"""Regression tests for gaps found while reviewing v1.1.0 against SRS 1.1."""
from __future__ import annotations

import warnings

import pytest
from conftest import QuietHandler
from mock_server import Handler as MockHandler

from owasp_scanner import cli
from owasp_scanner.checks import exposure


def ids(findings):
    return [f.id for f in findings]


# FR-CLI-01: a hostname without scheme gets https:// — including host:port forms,
# which urlparse() on Python >= 3.9 reads as "scheme:path".
@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "https://example.com/"),
        ("example.com:8443", "https://example.com:8443/"),
        ("localhost:8080", "https://localhost:8080/"),
        ("127.0.0.1:8899", "https://127.0.0.1:8899/"),
        ("http://example.com", "http://example.com/"),
        ("https://example.com/app", "https://example.com/app/"),
        ("https://example.com/app/?q=1", "https://example.com/app/?q=1"),
        ("https://example.com/app?q=1", "https://example.com/app/?q=1"),
    ],
)
def test_normalize_target(raw, expected):
    assert cli._normalize_target(raw) == expected


# FR-REPORT-05 / NFR-REL-01: one failing check must not abort the scan.
def test_failing_check_is_recorded_and_scan_continues(http_server, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("simulated parser bug")

    monkeypatch.setattr(cli.cors_check, "check_cors", boom)
    result = cli.run_scan(http_server(MockHandler))
    assert any("cors" in e and "simulated parser bug" in e for e in result.errors)
    assert "EXPOSURE-ENV" in ids(result.findings)  # later checks still ran
    assert result.finished_at


# AT-11 still holds for https:// targets: a plain connection failure is an error,
# not a TLS finding — the TLS check only runs when the baseline failed in TLS.
def test_unreachable_https_target_has_no_findings(closed_port):
    result = cli.run_scan(f"https://127.0.0.1:{closed_port}/", timeout=2)
    assert result.findings == [] and len(result.errors) == 1
    assert "tls" not in result.checks_run


# FR-COOKIE-01: evaluate each Set-Cookie header with its real attributes,
# including cookies set on redirect hops before the final page.
class MultiCookieHandler(QuietHandler):
    def do_GET(self):
        if self.path == "/":
            self.send(302, b"", [
                ("Location", "/home"),
                ("Set-Cookie", "hop=1; Secure; HttpOnly; SameSite=Lax"),
                ("Set-Cookie", "hop_weak=1; Path=/"),
            ])
        elif self.path == "/home":
            self.send(200, b"home", [
                ("Set-Cookie", "good=1; Secure; HttpOnly; SameSite=Strict"),
                ("Set-Cookie", "bad=1; Path=/"),
            ])
        else:
            self.send(404)


def test_cookies_use_real_attributes_across_redirects(http_server):
    result = cli.run_scan(http_server(MultiCookieHandler))
    cookie_findings = [f for f in result.findings if f.id == "COOKIE-FLAGS-MISSING"]
    flagged = sorted(f.title.split("'")[1] for f in cookie_findings)
    assert flagged == ["bad", "hop_weak"]
    assert all("; Path=/" in f.evidence for f in cookie_findings)  # verbatim header, not name=value


class RedirectOnlyCookieHandler(QuietHandler):
    def do_GET(self):
        if self.path == "/":
            self.send(302, b"", [("Location", "/home"), ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")])
        else:
            self.send(200 if self.path == "/home" else 404, b"home")


def test_hardened_cookie_on_redirect_hop_is_not_flagged(http_server):
    result = cli.run_scan(http_server(RedirectOnlyCookieHandler))
    assert "COOKIE-FLAGS-MISSING" not in ids(result.findings)


# FR-EXP-03: with soft-404, a 200 for security.txt proves nothing either.
def test_soft_404_does_not_claim_security_txt(http_server):
    class H(QuietHandler):
        def do_GET(self):
            self.send(200, b"catch-all")

    found = exposure.check_sensitive_paths(cli.build_session(timeout=2), http_server(H))
    assert found == []


# Timestamps stay ISO 8601 UTC with a Z suffix, without deprecated utcnow().
def test_timestamps_without_deprecation_warning(http_server):
    base = http_server(MockHandler)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        result = cli.run_scan(base)
    assert result.started_at.endswith("Z") and "+" not in result.started_at
