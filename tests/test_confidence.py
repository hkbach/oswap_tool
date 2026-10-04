"""FR-DET-03 (confidence of content-verified findings) and FR-DET-16 (TLS interception warning)."""

from __future__ import annotations

import pytest
from conftest import QuietHandler, skip_if_tls_is_intercepted

from websec_scanner import catalog, cli, rule_loader
from websec_scanner.checks import tls_check


class Ok(QuietHandler):
    def do_GET(self):
        self.send(200, b"ok")


# --- FR-DET-03 ---------------------------------------------------------------------


def test_content_verified_exposure_findings_are_high_confidence():
    for rule in rule_loader.load_sensitive_paths().paths:
        assert catalog.FINDING_CATALOG[rule.id].confidence == "high", rule.id


def test_hint_only_findings_stay_low_confidence():
    for finding_id in ("EXPOSURE-ROBOTS-HINTS", "EXPOSURE-SITEMAP-HINTS"):
        assert catalog.FINDING_CATALOG[finding_id].confidence == "low"


def test_scanned_exposure_finding_is_high_confidence(http_server):
    class H(QuietHandler):
        def do_GET(self):
            self.send(200, b"DB_PASSWORD=fake\n") if self.path == "/.env" else self.send(404)

    result = cli.run_scan(http_server(H), timeout=5)
    (env,) = [f for f in result.findings if f.id == "EXPOSURE-ENV"]
    assert env.confidence == "high"


# --- FR-DET-16 ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "issuer, intercepted",
    [
        ("CN=Avast Web/Mail Shield Root,O=Avast Web/Mail Shield", True),
        ("CN=Zscaler Intermediate Root CA,O=Zscaler Inc.", True),
        ("CN=FortiGate CA,O=Fortinet", True),
        ("CN=mitmproxy,O=mitmproxy", True),
        ("CN=GlobalSign Atlas R3 DV TLS CA 2025 Q4,O=GlobalSign nv-sa,C=BE", False),
        ("CN=R11,O=Let's Encrypt,C=US", False),
        ("CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US", False),
        ("CN=Sectigo RSA Domain Validation Secure Server CA,O=Sectigo Limited", False),
    ],
)
def test_interceptor_issuers_are_recognised(issuer, intercepted):
    assert rule_loader.is_interceptor_issuer(issuer) is intercepted


def test_intercepted_tls_is_flagged_and_findings_are_low_confidence(https_server):
    _, port = https_server(Ok, cert="expired", common_name="Avast Web/Mail Shield Root")
    warnings: list[str] = []
    findings = tls_check.check_tls("127.0.0.1", port, timeout=5, warnings=warnings)
    assert len(warnings) == 1 and "intercepted" in warnings[0] and "Avast" in warnings[0]
    assert f"127.0.0.1:{port}" in warnings[0]  # FR-TLS-11: say which endpoint it was
    assert findings and all(f.confidence == "low" for f in findings)


def test_run_scan_reports_the_interception_warning(https_server):
    base, _ = https_server(Ok, cert="valid", common_name="Zscaler Intermediate Root CA")
    result = cli.run_scan(base, timeout=5)
    assert any("intercepted" in e for e in result.errors)
    assert all(f.confidence == "low" for f in result.findings if f.id.startswith("TLS-"))


def test_normal_certificate_gives_no_warning(https_server, tmp_path):
    _, port = https_server(Ok, cert="valid")
    skip_if_tls_is_intercepted(port, tmp_path / "valid.pem")  # real interception would (rightly) warn
    warnings: list[str] = []
    findings = tls_check.check_tls("127.0.0.1", port, timeout=5, warnings=warnings)
    assert warnings == []
    assert all(catalog.enrich(f, "https://127.0.0.1/").confidence == "high" for f in findings)


def test_interceptor_list_is_data():
    rules = rule_loader.load_tls_interceptors()
    assert rules.version and rules.issuer_keywords
    assert all(k == k.lower() for k in rules.issuer_keywords)
