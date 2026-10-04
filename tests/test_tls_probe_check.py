"""FR-DET-04 (decision D7): the probes inside check_tls(), and the options around them.

Findings are one per weak protocol and one per weak cipher group, keyed host:port:<name>, so a
baseline and a suppression can tell "fixed 3DES, RC4 remains" apart. A probe that could not run
is an entry in ``errors``, never a silent "fine".
"""

from __future__ import annotations

import dataclasses
import threading

import pytest
import requests
from conftest import CERT_WINDOWS, QuietHandler, make_self_signed_cert
from mock_proxy import ProxyHandler, start_proxy
from mock_server import Handler as MockHandler
from tls_fake_server import Policy

from websec_scanner import catalog, cli, rule_loader, web
from websec_scanner.checks import tls_check

RULES = rule_loader.load_tls_probe()
PROBES = len(RULES.protocols) + sum(1 for g in RULES.groups if g.suites)
TLS10, TLS11, TLS12, TLS13 = 0x0301, 0x0302, 0x0303, 0x0304
MODERN = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)


def ids(findings):
    return [f.id for f in findings]


def keys(findings, finding_id):
    return [f.instance_key for f in findings if f.id == finding_id]


@pytest.fixture
def steps(monkeypatch, tmp_path):
    """Replace the two certificate connections, so a test sees the probes and nothing else."""

    def patch(protocol="TLSv1.2", cipher=MODERN, common_name="websec-scanner-test"):
        certfile, _ = make_self_signed_cert(tmp_path, *CERT_WINDOWS["valid"](), common_name=common_name)
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        der = x509.load_pem_x509_certificate(certfile.read_bytes()).public_bytes(Encoding.DER)
        monkeypatch.setattr(
            tls_check,
            "_fetch_raw_cert_and_connection_info",
            lambda h, p, t, limiter=None, proxy=None: (der, protocol, cipher, None),
        )
        monkeypatch.setattr(tls_check, "_verify_trust", lambda *args: None)

    return patch


def check(server, **kwargs):
    warnings: list[str] = []
    found = tls_check.check_tls("127.0.0.1", server.port, timeout=2, warnings=warnings, **kwargs)
    return found, warnings


# --- what the probes turn into -----------------------------------------------------------------------


def test_each_enabled_weak_protocol_and_group_is_its_own_finding(fake_tls, steps):
    steps()
    server = fake_tls(Policy(versions={TLS10, TLS11, TLS12}, suites={0x0005}))  # RC4_128_SHA only
    found, warnings = check(server)
    host = f"127.0.0.1:{server.port}"
    assert keys(found, "TLS-WEAK-PROTOCOL") == [f"{host}:TLSv1", f"{host}:TLSv1.1"]
    assert keys(found, "TLS-WEAK-CIPHER") == [f"{host}:RC4"]
    assert warnings == []
    assert ids(found) == ["TLS-WEAK-PROTOCOL", "TLS-WEAK-PROTOCOL", "TLS-WEAK-CIPHER"], "protocols first, in rule order"


def test_a_finding_says_what_was_seen_and_how(fake_tls, steps):
    steps()
    server = fake_tls(Policy(versions={TLS10, TLS12}, suites={0x0005}))
    found, _ = check(server)
    protocol = next(f for f in found if f.id == "TLS-WEAK-PROTOCOL")
    assert "TLSv1" in protocol.title and protocol.severity.value == "HIGH" and protocol.url.startswith("https://")
    assert "probe" in protocol.evidence and "TLSv1" in protocol.evidence
    cipher = next(f for f in found if f.id == "TLS-WEAK-CIPHER")
    assert "RC4" in cipher.title and "TLS_RSA_WITH_RC4_128_SHA" in cipher.evidence and "0x0005" in cipher.evidence
    assert cipher.recommendation and cipher.owasp_category.startswith("A02:2021")


def test_the_score_follows_the_reason_for_the_group(fake_tls, steps):
    steps()
    # NULL leaves nothing encrypted (catalog worst case); RC4 still encrypts (lowered vector).
    server = fake_tls(Policy(versions={TLS12}, suites={0x0001, 0x0005}))  # RSA_WITH_NULL_MD5, RSA_WITH_RC4_128_SHA
    found, _ = check(server)
    by_key = {f.instance_key.rsplit(":", 1)[1]: f for f in found if f.id == "TLS-WEAK-CIPHER"}
    assert set(by_key) == {"NULL", "RC4"}
    assert by_key["NULL"].cvss_vector == ""  # empty keeps the catalog's worst case
    assert by_key["RC4"].cvss_vector == catalog.CVSS_TLS_CIPHER_BROKEN_BUT_ENCRYPTING


# What a current server enables: AEAD suites only. (A fake that accepts whatever it is offered is not modern.)
MODERN_SUITES = {0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9, 0x009C, 0x009D, 0x1301, 0x1302, 0x1303}


def test_a_modern_server_gets_no_weak_findings(fake_tls, steps):
    steps()
    found, warnings = check(fake_tls(Policy(versions={TLS12, TLS13}, suites=MODERN_SUITES)))
    assert found == [] and warnings == []


def test_a_negotiated_weak_protocol_that_a_probe_confirms_is_one_finding_not_two(fake_tls, steps):
    steps(protocol="TLSv1")
    server = fake_tls(Policy(versions={TLS10, TLS12}))
    found, _ = check(server)
    assert keys(found, "TLS-WEAK-PROTOCOL") == [f"127.0.0.1:{server.port}:TLSv1"]


def test_the_negotiated_suite_and_the_probe_agree_on_one_group(fake_tls, steps):
    steps(cipher=("RC4-MD5", "TLSv1", 128))
    server = fake_tls(Policy(versions={TLS12}, suites={0x0004}))  # TLS_RSA_WITH_RC4_128_MD5
    found, _ = check(server)
    assert keys(found, "TLS-WEAK-CIPHER") == [f"127.0.0.1:{server.port}:RC4"]


def test_what_the_certificate_connection_saw_is_kept_when_the_probes_say_nothing(fake_tls, steps):
    steps(protocol="TLSv1", cipher=("RC4-MD5", "TLSv1", 128))
    server = fake_tls(Policy(behaviour="close"))  # every probe is refused
    found, _ = check(server)
    assert keys(found, "TLS-WEAK-PROTOCOL") == [f"127.0.0.1:{server.port}:TLSv1"]
    assert keys(found, "TLS-WEAK-CIPHER") == [f"127.0.0.1:{server.port}:RC4"]


def test_with_probes_off_only_the_negotiated_result_is_reported(fake_tls, steps):
    steps(protocol="TLSv1", cipher=("RC4-MD5", "TLSv1", 128))
    server = fake_tls(Policy(versions={TLS10, TLS11, TLS12}, suites={0x0005}))
    found, warnings = check(server, probe=False)
    assert server.connections == 0, "no probe may leave the scanner"
    assert keys(found, "TLS-WEAK-PROTOCOL") == [f"127.0.0.1:{server.port}:TLSv1"]
    assert keys(found, "TLS-WEAK-CIPHER") == [f"127.0.0.1:{server.port}:RC4"]
    assert warnings == []


def test_probes_are_not_attempted_when_the_certificate_connection_failed(fake_tls, monkeypatch):
    monkeypatch.setattr(
        tls_check, "_fetch_raw_cert_and_connection_info", lambda *a, **k: (None, None, None, OSError("refused"))
    )
    server = fake_tls(Policy(versions={TLS12}))
    found, _ = check(server)
    assert ids(found) == ["TLS-CONN-FAILED"] and server.connections == 0


# --- probes that could not run -----------------------------------------------------------------------


def test_probes_that_could_not_run_are_reported_once_per_reason(fake_tls, steps):
    steps()
    found, warnings = check(fake_tls(Policy(behaviour="http")))
    assert found == []
    assert len(warnings) == 1, warnings
    assert "Could not test" in warnings[0] and "not a TLS" in warnings[0]
    assert "SSLv3" in warnings[0] and "RC4" in warnings[0]


def test_a_server_answering_with_a_suite_it_was_not_offered_yields_no_finding_only_a_note(fake_tls, steps):
    steps()
    found, warnings = check(fake_tls(Policy(versions={TLS12}, force_suite=0xC02F)))
    assert "TLS-WEAK-CIPHER" not in ids(found)
    assert any("not offered" in w and "RC4" in w for w in warnings), warnings


def test_one_failing_probe_does_not_hide_the_others(fake_tls, steps):
    steps()
    server = fake_tls(Policy(versions={TLS10, TLS12}))
    found, warnings = check(server)
    assert keys(found, "TLS-WEAK-PROTOCOL") == [f"127.0.0.1:{server.port}:TLSv1"] and warnings == []


def test_when_the_connection_budget_runs_out_the_rest_is_reported_not_skipped_silently(fake_tls, steps, monkeypatch):
    steps()
    tight = dataclasses.replace(RULES, max_connections=5)
    monkeypatch.setattr(rule_loader, "load_tls_probe", lambda: tight)
    server = fake_tls(Policy(versions={TLS12}))
    _, warnings = check(server)
    assert server.connections == 3
    assert any("connection budget" in w for w in warnings)


def test_interception_lowers_the_confidence_of_probe_findings_too(fake_tls, steps):
    steps(common_name="Avast Web/Mail Shield Root")
    found, warnings = check(fake_tls(Policy(versions={TLS10, TLS12}, suites={0x0005})))
    assert found and all(f.confidence == "low" for f in found)
    assert any("intercepted" in w for w in warnings)


# --- against a real server, and through a proxy ------------------------------------------------------


def test_a_modern_real_server_costs_thirteen_connections_and_yields_no_weak_finding(https_server):
    _, port = https_server(QuietHandler, cert="valid")
    seen: list[str] = []

    class Counting:
        def acquire(self, url):
            seen.append(url)

    found = tls_check.check_tls("127.0.0.1", port, timeout=5, limiter=Counting())
    assert len(seen) == PROBES + 2 <= RULES.max_connections  # the certificate read, every probe, the trust check
    assert "TLS-WEAK-PROTOCOL" not in ids(found) and "TLS-WEAK-CIPHER" not in ids(found)
    assert ids(found) == ["TLS-CERT-NOT-TRUSTED"]  # the existing self-signed verdict is unchanged


def test_every_probe_goes_through_the_proxy(https_server):
    _, port = https_server(QuietHandler, cert="valid")
    proxy, proxy_url = start_proxy()
    try:
        tls_check.check_tls("127.0.0.1", port, timeout=5, proxy=proxy_url)
        with_probes = [t for m, t in ProxyHandler.seen if m == "CONNECT"]
        tls_check.check_tls("127.0.0.1", port, timeout=5, proxy=proxy_url, probe=False)
        total = [t for m, t in ProxyHandler.seen if m == "CONNECT"]
    finally:
        proxy.shutdown()
    assert len(with_probes) == PROBES + 2, "the two certificate connections and every probe, tunnelled"
    assert len(total) - len(with_probes) == 2, "with probes off, only the two certificate connections remain"


def test_run_scan_probes_by_default_and_can_be_told_not_to(https_server):
    url, _ = https_server(QuietHandler, cert="valid")
    on = cli.run_scan(url, groups=["tls"], timeout=5)
    off = cli.run_scan(url, groups=["tls"], timeout=5, tls_probe=False)
    assert on.limits["requests_sent"] - off.limits["requests_sent"] == PROBES


def test_max_requests_counts_probe_connections(https_server):
    url, _ = https_server(QuietHandler, cert="valid")
    result = cli.run_scan(url, groups=["tls"], timeout=5, max_requests=4)
    assert result.limits["stopped_by"] == "max-requests"


# --- options -----------------------------------------------------------------------------------------


def test_the_cli_flag_turns_probing_off(monkeypatch, http_server):
    seen: dict = {}
    real = cli.run_scan

    def spy(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "run_scan", spy)
    target = http_server(MockHandler)
    cli.main([target, "--yes", "--no-color", "--checks", "headers"])
    assert seen["tls_probe"] is True
    cli.main([target, "--yes", "--no-color", "--checks", "headers", "--no-tls-probe"])
    assert seen["tls_probe"] is False


def test_the_config_file_can_turn_it_off(tmp_path, monkeypatch, http_server):
    seen: dict = {}
    real = cli.run_scan
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: (seen.update(k), real(*a, **k))[1])
    config = tmp_path / "scanner.toml"
    config.write_text('tls_probe = false\nchecks = ["headers"]\n', encoding="utf-8")
    cli.main([http_server(MockHandler), "--yes", "--no-color", "--config", str(config)])
    assert seen["tls_probe"] is False


def _web(**kwargs):
    server = web.build_server("127.0.0.1", 0, timeout=5, **kwargs)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_the_web_ui_probes_unless_the_operator_started_it_without(monkeypatch, http_server):
    seen: list = []
    real = web.run_scan
    monkeypatch.setattr(web, "run_scan", lambda *a, **k: (seen.append(k.get("tls_probe")), real(*a, **k))[1])
    for kwargs, expected in (({}, True), ({"tls_probe": False}, False)):
        server, ui = _web(**kwargs)
        try:
            payload = {"target": http_server(MockHandler), "authorized": True, "checks": ["headers"]}
            assert requests.post(f"{ui}/api/scan", json=payload, timeout=60).status_code == 200
        finally:
            server.shutdown()
            server.server_close()
        assert seen[-1] is expected


def test_a_browser_cannot_switch_probing_back_on_or_off(http_server):
    server, ui = _web()
    try:
        payload = {"target": http_server(MockHandler), "authorized": True, "tls_probe": False}
        resp = requests.post(f"{ui}/api/scan", json=payload, timeout=60)
    finally:
        server.shutdown()
        server.server_close()
    assert resp.status_code == 400 and resp.json()["code"] == "unknown_field"


# --- what the user is told ---------------------------------------------------------------------------


def test_the_group_description_states_the_connection_ceiling():
    description = next(g for g in catalog.CHECK_GROUPS if g.id == "tls").description
    assert f"up to {PROBES + 2} TLS connections" in description


def test_the_consent_banner_tells_the_operator_about_legacy_handshakes():
    banner = cli.CONSENT_BANNER.lower()
    assert "handshake" in banner and "legacy" in banner
    assert f"{PROBES + 2}" in cli.CONSENT_BANNER


def test_sslv2_is_not_probed_and_the_rules_say_why():
    assert "SSLv2" not in [p.name for p in RULES.protocols]
    assert "SSLv2" in rule_loader.RULES_DIR.joinpath("tls_probe.json").read_text(encoding="utf-8")
