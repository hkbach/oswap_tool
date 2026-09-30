"""Unit tests for individual check modules (FR-HDR, FR-COOKIE, FR-TLS, FR-REDIR, FR-CORS, FR-EXP)."""
from __future__ import annotations

import pytest
from conftest import CERT_WINDOWS, QuietHandler, make_self_signed_cert

from owasp_scanner.checks import cookies, cors_check, exposure, headers, redirect_check, tls_check
from owasp_scanner.http_utils import USER_AGENT, build_session


def ids(findings):
    return sorted(f.id for f in findings)


# --- headers ---------------------------------------------------------------------

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}


def test_headers_fully_hardened_response_has_no_findings():
    assert headers.check_security_headers("https://t/", SECURE_HEADERS) == []


def test_headers_are_case_insensitive():
    lowered = {k.lower(): v for k, v in SECURE_HEADERS.items()}
    assert headers.check_security_headers("https://t/", lowered) == []


def test_headers_xfo_weak_value():
    hdrs = dict(SECURE_HEADERS, **{"X-Frame-Options": "ALLOWALL"})
    assert ids(headers.check_security_headers("https://t/", hdrs)) == ["HDR-XFO-WEAK"]


def test_headers_xfo_value_is_case_insensitive():
    hdrs = dict(SECURE_HEADERS, **{"X-Frame-Options": "sameOrigin"})
    assert headers.check_security_headers("https://t/", hdrs) == []


@pytest.mark.parametrize("csp", ["script-src 'unsafe-inline'", "script-src 'UNSAFE-EVAL'"])
def test_headers_csp_unsafe(csp):
    hdrs = dict(SECURE_HEADERS, **{"Content-Security-Policy": csp})
    found = headers.check_security_headers("https://t/", hdrs)
    assert ids(found) == ["HDR-CSP-UNSAFE"]
    assert found[0].owasp_category.startswith("A03:2021")


@pytest.mark.parametrize("value, flagged", [("1; mode=block", True), ("0", False)])
def test_headers_x_xss_protection(value, flagged):
    hdrs = dict(SECURE_HEADERS, **{"X-XSS-Protection": value})
    assert ("HDR-XXP-LEGACY" in ids(headers.check_security_headers("https://t/", hdrs))) is flagged


def test_headers_info_leak_one_finding_per_header():
    hdrs = dict(SECURE_HEADERS, Server="nginx/1.18", **{"X-Powered-By": "Express", "X-AspNet-Version": "4.0"})
    found = headers.check_security_headers("https://t/", hdrs)
    assert ids(found) == ["HDR-INFO-SERVER", "HDR-INFO-X-ASPNET-VERSION", "HDR-INFO-X-POWERED-BY"]
    assert all(f.severity.value == "INFO" and f.evidence for f in found)


# --- cookies ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, severity, missing",
    [
        ("sid=1; Secure; HttpOnly; SameSite=Lax", None, None),
        ("sid=1; Secure; HttpOnly", "LOW", "SameSite"),
        ("sid=1; HttpOnly; SameSite=Strict", "MEDIUM", "Secure"),
        ("sid=1; Secure; SameSite=None", "MEDIUM", "HttpOnly"),
        ("sid=1; Secure; HttpOnly; SameSite=Bogus", "LOW", "SameSite(invalid value: Bogus)"),
    ],
)
def test_cookie_flags(raw, severity, missing):
    found = cookies.check_cookies("https://t/", [raw])
    if severity is None:
        assert found == []
        return
    assert len(found) == 1
    assert found[0].severity.value == severity
    assert missing in found[0].description
    assert found[0].evidence == raw  # FR-COOKIE-04: verbatim Set-Cookie


# --- TLS (real handshakes against local servers) ---------------------------------


class _Ok(QuietHandler):
    def do_GET(self):
        self.send(200, b"ok")


def test_tls_expired_cert_reports_only_expired(https_server):
    _, port = https_server(_Ok, cert="expired")
    assert ids(tls_check.check_tls("127.0.0.1", port, timeout=5)) == ["TLS-CERT-EXPIRED"]


def test_tls_not_yet_valid_cert(https_server):
    _, port = https_server(_Ok, cert="not_yet_valid")
    assert ids(tls_check.check_tls("127.0.0.1", port, timeout=5)) == ["TLS-CERT-NOT-YET-VALID"]


def test_tls_untrusted_cert_reports_only_not_trusted(https_server):
    _, port = https_server(_Ok, cert="valid")
    assert ids(tls_check.check_tls("127.0.0.1", port, timeout=5)) == ["TLS-CERT-NOT-TRUSTED"]


def test_tls_expiring_soon(https_server):
    _, port = https_server(_Ok, cert="expiring")
    found = tls_check.check_tls("127.0.0.1", port, timeout=5)
    assert ids(found) == ["TLS-CERT-EXPIRING-SOON", "TLS-CERT-NOT-TRUSTED"]


def test_tls_connection_failure_stops_tls_checks(closed_port):
    assert ids(tls_check.check_tls("127.0.0.1", closed_port, timeout=2)) == ["TLS-CONN-FAILED"]


def test_tls_weak_protocol_and_cipher(monkeypatch, tmp_path):
    # Modern OpenSSL refuses to negotiate these, so feed step A's result directly.
    certfile, _ = make_self_signed_cert(tmp_path, *CERT_WINDOWS["valid"]())
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    der = x509.load_pem_x509_certificate(certfile.read_bytes()).public_bytes(Encoding.DER)
    monkeypatch.setattr(
        tls_check, "_fetch_raw_cert_and_connection_info",
        lambda h, p, t: (der, "TLSv1", ("RC4-MD5", "TLSv1", 128), None),
    )
    monkeypatch.setattr(tls_check, "_verify_trust", lambda h, p, t: None)
    assert ids(tls_check.check_tls("h", 443)) == ["TLS-WEAK-CIPHER", "TLS-WEAK-PROTOCOL"]


def test_tls_expiry_threshold_constant():
    assert tls_check._CERT_EXPIRY_WARN_DAYS == 30


# --- redirect --------------------------------------------------------------------


class _NoRedirect(QuietHandler):
    def do_GET(self):
        self.send(200, b"plain http")


class _RedirectToHttps(QuietHandler):
    def do_GET(self):
        self.send(301, b"", {"Location": "https://127.0.0.1:1/"})


def test_redirect_missing_https_redirect(http_server):
    host = http_server(_NoRedirect)[len("http://"):-1]  # "127.0.0.1:<port>"
    found = redirect_check.check_http_to_https_redirect(build_session(timeout=2), host)
    assert ids(found) == ["TLS-NO-HTTPS-REDIRECT"]


def test_redirect_to_https_is_not_a_finding(http_server):
    # The HTTPS hop fails to connect; the final URL we saw was never HTTPS-verified,
    # but FR-REDIR-02 treats "no response" as acceptable, so nothing is reported.
    host = http_server(_RedirectToHttps)[len("http://"):-1]
    assert redirect_check.check_http_to_https_redirect(build_session(timeout=2), host) == []


def test_redirect_port_80_closed_is_not_a_finding(closed_port):
    host = f"127.0.0.1:{closed_port}"
    assert redirect_check.check_http_to_https_redirect(build_session(timeout=2), host) == []


# --- CORS ------------------------------------------------------------------------


def _cors_handler(acao, acac=None):
    class H(QuietHandler):
        def do_GET(self):
            hdrs = {}
            if acao is not None:
                hdrs["Access-Control-Allow-Origin"] = self.headers["Origin"] if acao == "echo" else acao
            if acac:
                hdrs["Access-Control-Allow-Credentials"] = acac
            self.send(200, b"ok", hdrs)

    return H


@pytest.mark.parametrize(
    "acao, acac, expected",
    [
        ("*", "true", ("CORS-WILDCARD-WITH-CREDENTIALS", "CRITICAL")),
        ("echo", "true", ("CORS-REFLECTS-ARBITRARY-ORIGIN", "HIGH")),
        ("echo", None, ("CORS-REFLECTS-ARBITRARY-ORIGIN", "MEDIUM")),
        ("*", None, ("CORS-WILDCARD", "INFO")),
        ("https://app.example", "true", None),
        (None, None, None),
    ],
)
def test_cors(http_server, acao, acac, expected):
    found = cors_check.check_cors(build_session(timeout=2), http_server(_cors_handler(acao, acac)))
    assert [(f.id, f.severity.value) for f in found] == ([expected] if expected else [])


def test_cors_sends_placeholder_origin_and_scanner_user_agent(http_server):
    seen = {}

    class H(QuietHandler):
        def do_GET(self):
            seen["origin"] = self.headers.get("Origin")
            seen["ua"] = self.headers.get("User-Agent")
            self.send(200, b"ok")

    cors_check.check_cors(build_session(timeout=2), http_server(H))
    assert seen["origin"].endswith(".invalid")  # FR-CORS-01
    assert seen["ua"] == USER_AGENT  # NFR-SEC-03


# --- exposure --------------------------------------------------------------------


def test_sensitive_paths_table_matches_srs_4_8_1():
    table = {path: (fid, sev.value) for path, (fid, sev, _) in exposure._SENSITIVE_PATHS.items()}
    assert len(table) == 17
    assert len({fid for fid, _ in table.values()}) == 17  # ids are unique
    assert table[".git/HEAD"] == ("EXPOSURE-GIT-HEAD", "CRITICAL")
    assert table[".DS_Store"] == ("EXPOSURE-DS-STORE", "LOW")
    assert table[".well-known/security.txt"] == ("EXPOSURE-SECURITY-TXT", "INFO")


def test_security_txt_is_positive_info(http_server):
    class H(QuietHandler):
        def do_GET(self):
            self.send(200 if self.path == "/.well-known/security.txt" else 404, b"Contact: x")

    found = exposure.check_sensitive_paths(build_session(timeout=2), http_server(H))
    assert [(f.id, f.severity.value) for f in found] == [("EXPOSURE-SECURITY-TXT", "INFO")]


def test_sensitive_paths_respects_worker_limit(http_server, monkeypatch):
    created = {}
    real = exposure.ThreadPoolExecutor

    def spy(max_workers):
        created["max_workers"] = max_workers
        return real(max_workers=max_workers)

    monkeypatch.setattr(exposure, "ThreadPoolExecutor", spy)

    class H(QuietHandler):
        def do_GET(self):
            self.send(404)

    exposure.check_sensitive_paths(build_session(timeout=2), http_server(H), max_workers=3)
    assert created["max_workers"] == 3


def test_robots_hints_capped_at_ten(http_server):
    body = "\n".join(f"Disallow: /admin{i}/" for i in range(15)).encode()

    class H(QuietHandler):
        def do_GET(self):
            self.send(200 if self.path == "/robots.txt" else 404, body)

    found = exposure.check_robots_and_sitemap(build_session(timeout=2), http_server(H))
    assert len(found) == 1 and len(found[0].evidence.split(", ")) == 10
