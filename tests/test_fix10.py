"""FR-FIX-10: headers are judged on the final response; HSTS on HTTPS only, plus the start host."""

from __future__ import annotations

import json

import pytest
from conftest import QuietHandler, skip_if_tls_is_intercepted

from websec_scanner import cli, output
from websec_scanner.checks import headers
from websec_scanner.models import SCHEMA_VERSION


class PlainHandler(QuietHandler):
    def do_GET(self):
        self.send(200, b"ok", {"Content-Type": "text/html"})


def _redirect_to(location: str):
    class H(QuietHandler):
        def do_GET(self):
            if self.path.startswith("/home"):
                self.send(200, b"home", {"Content-Type": "text/html"})
            elif self.path.split("?")[0] == "/":
                self.send(302, b"", {"Location": location})
            else:
                self.send(404)

    return H


def ids(findings):
    return [f.id for f in findings]


def test_report_records_final_url_and_redirect_chain(http_server):
    base = http_server(_redirect_to("/home"))
    report = output.build_report(cli.run_scan(base, timeout=5))
    assert report["schema_version"] == SCHEMA_VERSION
    assert report["final_url"] == base + "home"
    assert report["redirect_chain"] == [{"url": base, "status": 302}]


def test_no_redirect_gives_empty_chain(http_server):
    base = http_server(PlainHandler)
    report = output.build_report(cli.run_scan(base, timeout=5))
    assert report["final_url"] == base and report["redirect_chain"] == []


def test_failed_baseline_has_no_final_url(closed_port):
    report = output.build_report(cli.run_scan(f"http://127.0.0.1:{closed_port}/", timeout=2))
    assert report["final_url"] == "" and report["redirect_chain"] == []


def test_final_url_and_chain_are_redacted(http_server):
    secret = "Chain-Token-4242"  # noqa: S105 - fake value the leak check searches for
    base = http_server(_redirect_to(f"/home?token={secret}"))
    report = output.build_report(cli.run_scan(base + f"?session={secret}", timeout=5))
    assert secret not in json.dumps(report)


def test_hsts_is_not_required_when_the_final_response_is_http(http_server):
    result = cli.run_scan(http_server(_redirect_to("/home")), timeout=5)
    assert "HDR-STRICT-TRANSPORT-SECURITY-MISSING" not in ids(result.findings)


def test_http_target_redirected_to_https_is_held_to_hsts(http_server, https_server, tmp_path, monkeypatch):
    https_base, https_port = https_server(PlainHandler, cert="valid")
    skip_if_tls_is_intercepted(https_port, tmp_path / "valid.pem")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "valid.pem"))
    result = cli.run_scan(http_server(_redirect_to(https_base)), timeout=5)
    assert "HDR-STRICT-TRANSPORT-SECURITY-MISSING" in ids(result.findings)  # final response is HTTPS


# --- HSTS on the start host when the redirect changed host ----------------------------


class _Resp:
    def __init__(self, hdrs):
        self.headers = hdrs
        self.status_code = 301


def _fake_get(monkeypatch, response=None, error=None):
    calls = []

    def fake(session, url, **kwargs):
        calls.append((url, kwargs))
        return response, error

    monkeypatch.setattr(headers, "safe_get", fake)
    return calls


def test_start_host_without_hsts_is_reported(monkeypatch):
    calls = _fake_get(monkeypatch, _Resp({"Location": "https://www.example.com/"}))
    (finding,) = headers.check_start_host_hsts(None, "http://example.com/", "https://www.example.com/")
    assert calls == [("https://example.com/", {"allow_redirects": False})]
    assert finding.id == "HDR-HSTS-MISSING-ON-START-HOST"
    assert finding.severity.value == "LOW"
    assert finding.instance_key == "example.com"


def test_start_host_with_hsts_is_fine(monkeypatch):
    _fake_get(monkeypatch, _Resp({"Strict-Transport-Security": "max-age=31536000"}))
    assert headers.check_start_host_hsts(None, "https://example.com/", "https://www.example.com/") == []


def test_start_host_keeps_an_explicit_https_port(monkeypatch):
    calls = _fake_get(monkeypatch, _Resp({}))
    headers.check_start_host_hsts(None, "https://example.com:8443/app/", "https://www.example.com:8443/app/")
    assert calls[0][0] == "https://example.com:8443/"


@pytest.mark.parametrize(
    "start, final",
    [
        ("https://example.com/", "https://example.com/home"),  # same host
        ("http://example.com/", "http://www.example.com/"),  # final is not HTTPS
        ("https://Example.com/", "https://example.com/"),  # case only
    ],
)
def test_start_host_check_does_not_apply(monkeypatch, start, final):
    calls = _fake_get(monkeypatch, _Resp({}))
    assert headers.check_start_host_hsts(None, start, final) == []
    assert calls == []  # no request sent


def test_unreachable_start_host_is_an_error_not_a_finding(monkeypatch):
    _fake_get(monkeypatch, error="connection refused")
    with pytest.raises(RuntimeError, match="connection refused"):
        headers.check_start_host_hsts(None, "http://example.com/", "https://www.example.com/")


def test_html_report_shows_the_final_url_when_redirected(http_server):
    from websec_scanner.html_report import render_html

    base = http_server(_redirect_to("/home"))
    html = render_html(output.build_report(cli.run_scan(base, timeout=5)))
    assert "<th>Final URL</th>" in html and base + "home" in html
