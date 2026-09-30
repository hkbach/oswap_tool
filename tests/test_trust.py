"""FR-CI-10: one trust decision for HTTP requests and the TLS check (fixes B1)."""

from __future__ import annotations

import ssl
import sys

import pytest
import requests
from conftest import QuietHandler, skip_if_tls_is_intercepted

from owasp_scanner import cli, http_utils


class Ok(QuietHandler):
    def do_GET(self):
        self.send(200, b"ok", {"Content-Type": "text/html"})


def ids(findings):
    return [f.id for f in findings]


def test_default_trust_is_the_os_store_not_certifi(monkeypatch):
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    ctx = http_utils.trust_context()
    assert ctx.verify_mode.name == "CERT_REQUIRED" and ctx.check_hostname
    if sys.platform == "win32":  # Windows loads its store eagerly; OpenSSL on Linux reads a directory lazily
        certifi_cas = ssl.create_default_context(cafile=requests.certs.where()).get_ca_certs()
        assert ctx.get_ca_certs() and ctx.get_ca_certs() != certifi_cas


def test_ca_bundle_replaces_the_default_store(tmp_path, https_server):
    https_server(Ok, cert="valid")  # writes valid.pem
    ctx = http_utils.trust_context(str(tmp_path / "valid.pem"))
    assert len(ctx.get_ca_certs()) == 1


def test_env_variables_are_honoured(tmp_path, https_server, monkeypatch):
    https_server(Ok, cert="valid")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "valid.pem"))
    assert len(http_utils.trust_context().get_ca_certs()) == 1


def test_requests_never_adds_certifi_to_the_shared_context(tmp_path, https_server):
    base, _ = https_server(Ok, cert="valid")
    session = http_utils.build_session(timeout=5, ca_bundle=str(tmp_path / "valid.pem"))
    http_utils.safe_get(session, base)  # may fail if TLS is intercepted; that is fine here
    assert len(session.trust_context.get_ca_certs()) == 1


def test_without_ca_bundle_a_private_ca_is_not_trusted(https_server):
    base, _ = https_server(Ok, cert="valid")
    result = cli.run_scan(base, timeout=5)
    assert any(e.startswith("Could not fetch") for e in result.errors)
    assert "TLS-CERT-NOT-TRUSTED" in ids(result.findings)


def test_ca_bundle_trusts_a_private_ca_for_http_and_tls(https_server, tmp_path):
    base, port = https_server(Ok, cert="valid")
    skip_if_tls_is_intercepted(port, tmp_path / "valid.pem")
    result = cli.run_scan(base, timeout=5, ca_bundle=str(tmp_path / "valid.pem"))
    assert not [e for e in result.errors if e.startswith("Could not fetch")]  # HTTP trusted it
    assert "security-headers" in result.checks_run  # so the HTTP checks ran
    assert "TLS-CERT-NOT-TRUSTED" not in ids(result.findings)  # and the TLS check agreed


def test_cli_ca_bundle_option(https_server, tmp_path, capsys):
    base, port = https_server(Ok, cert="valid")
    skip_if_tls_is_intercepted(port, tmp_path / "valid.pem")
    cli.main([base, "--yes", "--no-color", "--ca-bundle", str(tmp_path / "valid.pem")])
    assert "TLS certificate chain failed trust validation" not in capsys.readouterr().out


@pytest.mark.parametrize("content", [None, b"not a certificate"])
def test_cli_rejects_a_missing_or_invalid_bundle(tmp_path, capsys, content):
    bundle = tmp_path / "bundle.pem"
    if content is not None:
        bundle.write_bytes(content)
    with pytest.raises(SystemExit) as exc:
        cli.main(["https://example.invalid", "--yes", "--ca-bundle", str(bundle)])
    assert exc.value.code == 2 and "--ca-bundle" in capsys.readouterr().err
