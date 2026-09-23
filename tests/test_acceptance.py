"""Acceptance scenarios AT-01 … AT-18 from SRS 1.1 section 9, run offline."""
from __future__ import annotations

import json

import pytest
from conftest import QuietHandler
from mock_server import Handler as MockHandler

from owasp_scanner import cli
from owasp_scanner.checks import headers

ANSI = "\x1b["


def ids(findings):
    return [f.id for f in findings]


def by_id(findings, finding_id):
    matches = [f for f in findings if f.id == finding_id]
    assert matches, f"{finding_id} not in {ids(findings)}"
    return matches[0]


class SoftNotFoundHandler(QuietHandler):
    """Returns HTTP 200 for every path, like a SPA catch-all route."""

    def do_GET(self):
        self.send(200, b"<html><body>Welcome</body></html>", {"Content-Type": "text/html"})


class CorsReflectHandler(QuietHandler):
    def do_GET(self):
        hdrs = {"Content-Type": "text/html"}
        if self.path == "/" and self.headers.get("Origin"):
            hdrs["Access-Control-Allow-Origin"] = self.headers["Origin"]
            hdrs["Access-Control-Allow-Credentials"] = "true"
        self.send(200 if self.path == "/" else 404, b"ok", hdrs)


class SitemapHandler(QuietHandler):
    def do_GET(self):
        if self.path == "/sitemap.xml":
            host = self.headers["Host"]
            body = (
                '<?xml version="1.0"?><urlset>'
                f"<url><loc>http://{host}/about</loc></url>"
                f"<url><loc>http://{host}/staging/internal-tool</loc></url>"
                "</urlset>"
            ).encode()
            self.send(200, body, {"Content-Type": "application/xml"})
        else:
            self.send(200 if self.path == "/" else 404, b"ok", {"Content-Type": "text/html"})


# --- AT-01 / AT-02: consent gate -------------------------------------------------


@pytest.mark.parametrize("answer", ["no", "", "n", "maybe"])
def test_at01_refusing_consent_sends_nothing_and_exits_2(monkeypatch, answer):
    monkeypatch.setattr("builtins.input", lambda prompt="": answer)

    def must_not_run(*a, **kw):
        raise AssertionError("no request may be sent without consent")

    monkeypatch.setattr(cli, "run_scan", must_not_run)
    monkeypatch.setattr(cli, "build_session", must_not_run)
    assert cli.main(["https://example.invalid"]) == 2


def test_at01_eof_on_prompt_counts_as_refusal(monkeypatch):
    def eof(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    monkeypatch.setattr(cli, "run_scan", lambda *a, **kw: pytest.fail("scan ran without consent"))
    assert cli.main(["https://example.invalid"]) == 2


@pytest.mark.parametrize("answer", ["y", "YES", " yes "])
def test_consent_accepts_y_and_yes_case_insensitive(monkeypatch, http_server, answer):
    base = http_server(MockHandler)
    monkeypatch.setattr("builtins.input", lambda prompt="": answer)
    assert cli.main([base, "--no-color"]) == 1


def test_at02_yes_flag_skips_prompt(monkeypatch, http_server, capsys):
    base = http_server(MockHandler)
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("prompted despite --yes"))
    cli.main([base, "--yes", "--no-color"])
    out = capsys.readouterr().out
    assert "only run it against systems you own" in out  # banner still shown (FR-CONSENT-01)
    assert "OWASP-aligned scan report" in out


# --- AT-03 … AT-09: HTTP checks against local mock servers -----------------------


def test_at03_all_security_headers_missing():
    findings = headers.check_security_headers("https://t.example/", {}, is_https=True)
    severities = {f.id: f.severity.value for f in findings}
    assert severities == {
        "HDR-STRICT-TRANSPORT-SECURITY-MISSING": "HIGH",
        "HDR-CONTENT-SECURITY-POLICY-MISSING": "MEDIUM",
        "HDR-X-CONTENT-TYPE-OPTIONS-MISSING": "LOW",
        "HDR-X-FRAME-OPTIONS-MISSING": "MEDIUM",
        "HDR-REFERRER-POLICY-MISSING": "LOW",
        "HDR-PERMISSIONS-POLICY-MISSING": "INFO",
    }


def test_at04_cookie_missing_flags(http_server):
    result = cli.run_scan(http_server(MockHandler))
    cookie = by_id(result.findings, "COOKIE-FLAGS-MISSING")
    assert cookie.severity.value == "MEDIUM"
    assert "Secure, HttpOnly, SameSite" in cookie.description
    assert cookie.evidence == "session=abc123; Path=/"


def test_at05_exposed_env_and_git_head(http_server):
    result = cli.run_scan(http_server(MockHandler))
    for finding_id in ("EXPOSURE-ENV", "EXPOSURE-GIT-HEAD"):
        f = by_id(result.findings, finding_id)
        assert f.severity.value == "CRITICAL"
        assert f.owasp_category.startswith("A01:2021")
    exposure_ids = [i for i in ids(result.findings) if i.startswith("EXPOSURE-") and i not in (
        "EXPOSURE-DIR-LISTING", "EXPOSURE-ROBOTS-HINTS")]
    assert sorted(exposure_ids) == ["EXPOSURE-ENV", "EXPOSURE-GIT-HEAD"]


def test_at06_soft_404_suppresses_exposure_findings(http_server):
    result = cli.run_scan(http_server(SoftNotFoundHandler))
    leaked = [f for f in result.findings if f.owasp_category.startswith("A01:2021")]
    assert leaked == []


def test_at07_directory_listing(http_server):
    result = cli.run_scan(http_server(MockHandler))
    listing = by_id(result.findings, "EXPOSURE-DIR-LISTING")
    assert listing.severity.value == "MEDIUM"
    assert listing.url.endswith("/images/")


def test_at08_robots_txt_hints(http_server):
    result = cli.run_scan(http_server(MockHandler))
    robots = by_id(result.findings, "EXPOSURE-ROBOTS-HINTS")
    assert robots.severity.value == "LOW"
    assert robots.evidence == "/admin/, /backup/"


def test_at09_cors_reflects_origin_with_credentials(http_server):
    result = cli.run_scan(http_server(CorsReflectHandler))
    cors = by_id(result.findings, "CORS-REFLECTS-ARBITRARY-ORIGIN")
    assert cors.severity.value == "HIGH"


# --- AT-10 / AT-15: TLS, through the full CLI flow -------------------------------


def test_at10_expired_certificate_end_to_end(https_server, capsys):
    base, _ = https_server(SoftNotFoundHandler, cert="expired")
    exit_code = cli.main([base, "--yes", "--no-color", "--timeout", "5"])
    result_ids = capsys.readouterr().out
    assert "TLS certificate has expired" in result_ids
    assert "TLS certificate chain failed trust validation" not in result_ids
    assert exit_code == 1


def test_at15_untrusted_valid_certificate_end_to_end(https_server, capsys):
    base, _ = https_server(SoftNotFoundHandler, cert="valid")
    exit_code = cli.main([base, "--yes", "--no-color", "--timeout", "5"])
    out = capsys.readouterr().out
    assert "TLS certificate chain failed trust validation" in out
    assert "expired" not in out.lower()
    assert "not yet valid" not in out.lower()
    assert exit_code == 1


# --- AT-11 … AT-14: robustness and reporting -------------------------------------


def test_at11_unreachable_target(closed_port, capsys):
    target = f"http://127.0.0.1:{closed_port}/"
    result = cli.run_scan(target, timeout=2)
    assert result.findings == []
    assert len(result.errors) == 1 and target in result.errors[0]

    exit_code = cli.main([target, "--yes", "--no-color", "--timeout", "2"])
    out = capsys.readouterr().out
    assert "No findings." in out and "Non-fatal errors during scan" in out
    assert exit_code == 0  # per FR-CLI-04 as written; see docs/srs-feedback.md


def test_at12_json_report(http_server, tmp_path):
    out = tmp_path / "out.json"
    cli.main([http_server(MockHandler), "--yes", "--no-color", "--json", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert set(data) == {"target", "started_at", "finished_at", "checks_run", "summary", "findings", "errors"}
    assert set(data["summary"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    assert set(data["findings"][0]) == {
        "id", "title", "severity", "owasp_category", "description", "evidence", "recommendation", "url"}
    ranks = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    order = [ranks.index(f["severity"]) for f in data["findings"]]
    assert order == sorted(order)  # FR-REPORT-02
    assert data["started_at"].endswith("Z") and data["finished_at"].endswith("Z")


def test_at13_exit_code_1_on_critical(http_server):
    assert cli.main([http_server(MockHandler), "--yes", "--no-color"]) == 1


def test_exit_code_0_without_critical_or_high(http_server):
    # SoftNotFoundHandler over plain HTTP yields only MEDIUM/LOW/INFO header findings.
    assert cli.main([http_server(SoftNotFoundHandler), "--yes", "--no-color"]) == 0


def test_at14_no_color_output(http_server, capsys):
    base = http_server(MockHandler)
    cli.main([base, "--yes", "--no-color"])
    assert ANSI not in capsys.readouterr().out
    cli.main([base, "--yes"])
    assert ANSI in capsys.readouterr().out


# --- AT-16 … AT-18: behaviour changed in SRS 1.1 ---------------------------------


def test_at16_hsts_only_required_over_https(http_server):
    result = cli.run_scan(http_server(MockHandler))
    assert "HDR-STRICT-TRANSPORT-SECURITY-MISSING" not in ids(result.findings)
    over_https = headers.check_security_headers("https://t.example/", {}, is_https=True)
    assert "HDR-STRICT-TRANSPORT-SECURITY-MISSING" in ids(over_https)


@pytest.mark.parametrize("xfo", [None, "ALLOW-FROM https://x.example"])
def test_at17_frame_ancestors_suppresses_x_frame_options(xfo):
    hdrs = {"Content-Security-Policy": "frame-ancestors 'none'"}
    if xfo:
        hdrs["X-Frame-Options"] = xfo
    found = ids(headers.check_security_headers("https://t.example/", hdrs))
    assert not [i for i in found if "X-FRAME" in i or "XFO" in i]


def test_at18_sitemap_loc_hints(http_server):
    base = http_server(SitemapHandler)
    result = cli.run_scan(base)
    sitemap = by_id(result.findings, "EXPOSURE-SITEMAP-HINTS")
    assert sitemap.severity.value == "LOW"
    assert sitemap.evidence == f"{base}staging/internal-tool"
