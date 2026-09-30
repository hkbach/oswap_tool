"""FR-FIX-09: the HTTP -> HTTPS redirect check always runs, and TLS follows the redirect."""

from __future__ import annotations

from conftest import QuietHandler, skip_if_tls_is_intercepted

from owasp_scanner import cli, http_utils
from owasp_scanner.checks import redirect_check


def ids(findings):
    return [f.id for f in findings]


class PlainHandler(QuietHandler):
    def do_GET(self):
        self.send(200, b"plain http", {"Content-Type": "text/html"})


def _redirect_to(location: str):
    class H(QuietHandler):
        def do_GET(self):
            if self.path == "/":
                self.send(301, b"", {"Location": location})
            else:
                self.send(404)

    return H


def _http_to_https(http_server, https_server, cert):
    https_base, https_port = https_server(PlainHandler, cert=cert)
    return http_server(_redirect_to(https_base)), https_port


# --- target entered as http:// --------------------------------------------------------


def test_http_target_without_redirect_is_reported(http_server):
    result = cli.run_scan(http_server(PlainHandler), timeout=5)
    finding = next(f for f in result.findings if f.id == "TLS-NO-HTTPS-REDIRECT")
    assert finding.severity.value == "HIGH"
    assert "http-to-https-redirect" in result.checks_run
    assert "tls" not in result.checks_run  # nothing ever reached HTTPS


def test_http_target_redirected_to_https_with_bad_cert_reports_the_cert_not_the_redirect(http_server, https_server):
    target, https_port = _http_to_https(http_server, https_server, "valid")
    result = cli.run_scan(target, timeout=5)

    assert "TLS-NO-HTTPS-REDIRECT" not in ids(result.findings)  # it did redirect to HTTPS
    assert "http-to-https-redirect" in result.checks_run
    tls = next(f for f in result.findings if f.id == "TLS-CERT-NOT-TRUSTED")
    assert tls.instance_key == f"127.0.0.1:{https_port}"  # the HTTPS port we were sent to, not 443


def test_http_target_redirected_to_expired_https_reports_expiry(http_server, https_server):
    target, _ = _http_to_https(http_server, https_server, "expired")
    result = cli.run_scan(target, timeout=5)
    assert "TLS-CERT-EXPIRED" in ids(result.findings)
    assert "TLS-NO-HTTPS-REDIRECT" not in ids(result.findings)


def test_http_target_redirected_to_trusted_https_scans_the_https_page(http_server, https_server, tmp_path, monkeypatch):
    target, https_port = _http_to_https(http_server, https_server, "valid")
    skip_if_tls_is_intercepted(https_port, tmp_path / "valid.pem")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "valid.pem"))  # now both HTTP and TLS trust the test cert
    tls_calls = []
    real_check_tls = cli.tls_check.check_tls

    def spy(host, port=443, **kwargs):
        tls_calls.append((host, port))
        return real_check_tls(host, port=port, **kwargs)

    monkeypatch.setattr(cli.tls_check, "check_tls", spy)
    result = cli.run_scan(target, timeout=5)

    assert not [e for e in result.errors if e.startswith("Could not fetch")]
    assert "tls" in result.checks_run and "http-to-https-redirect" in result.checks_run
    assert "TLS-NO-HTTPS-REDIRECT" not in ids(result.findings)
    # HTTP and the TLS check share one trust decision (FR-CI-10), so the bundle that made the
    # redirect target trusted for HTTP makes the TLS check trust it too: no TLS finding at all.
    assert not [f for f in result.findings if f.id == "TLS-CERT-NOT-TRUSTED"]
    assert tls_calls == [("127.0.0.1", https_port)]  # TLS ran on the HTTPS port we were sent to


# --- target entered as https:// : probe http://<host>/ hop by hop -----------------------


def _host(base: str) -> str:
    return base[len("http://") : -1]  # "127.0.0.1:<port>"


def test_probe_counts_a_redirect_to_https_without_loading_it(http_server):
    # The HTTPS side does not even exist: certificate problems must not affect this check.
    host = _host(http_server(_redirect_to("https://127.0.0.1:1/")))
    session = http_utils.build_session(timeout=2, scope_host="127.0.0.1")
    assert redirect_check.check_http_to_https_redirect(session, host) == []


def test_probe_follows_http_hops_in_scope(http_server):
    final = http_server(PlainHandler)
    host = _host(http_server(_redirect_to(final)))
    session = http_utils.build_session(timeout=2, scope_host="127.0.0.1")
    (finding,) = redirect_check.check_http_to_https_redirect(session, host)
    assert finding.id == "TLS-NO-HTTPS-REDIRECT" and final in finding.description


def test_probe_stops_at_out_of_scope_redirect(http_server):
    host = _host(http_server(_redirect_to("http://outside.invalid/")))
    session = http_utils.build_session(timeout=2, scope_host="127.0.0.1")
    assert redirect_check.check_http_to_https_redirect(session, host) == []
    assert "outside.invalid" in session.blocked_redirects
