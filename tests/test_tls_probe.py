"""FR-DET-04 (decision D7): the hand-built ClientHello, reading the reply, and the probe run.

What a probe must do, and must not do:
* it sends exactly one TLS record (a ClientHello), reads the first reply and closes;
* it never completes a handshake and never sends application data;
* it counts as a connection for every limit (rate, max requests, its own ceiling);
* a server that cannot be reached, or does not answer, is reported as "could not test",
  never as "not enabled".

The builder is checked three ways: against the independent parser in tests/tls_fake_server.py,
against a real OpenSSL server that must answer it, and the parser against a real OpenSSL client.
"""

from __future__ import annotations

import dataclasses
import socket
import ssl
import threading
import time

import pytest
from conftest import QuietHandler
from tls_fake_server import (
    EXT_SERVER_NAME,
    HELLO_RETRY_REQUEST_RANDOM,
    SCSV,
    Policy,
    alert,
    server_hello,
)

from websec_scanner import rule_loader
from websec_scanner.checks import tls_probe
from websec_scanner.checks.tls_probe import Outcome
from websec_scanner.limits import ScanLimiter, ScanLimitReached

RULES = rule_loader.load_tls_probe()
PROTOCOLS = {p.name: p for p in RULES.protocols}
GROUPS = {g.id: g for g in RULES.groups}
PROBES = len(RULES.protocols) + sum(1 for g in RULES.groups if g.suites)
TLS10, TLS11, TLS12, TLS13, SSL3 = 0x0301, 0x0302, 0x0303, 0x0304, 0x0300
NO_PAUSE = {"sleep": lambda seconds: None}


def _parse(raw: bytes):
    from tls_fake_server import parse_client_hello

    return parse_client_hello(raw)


# --- the ClientHello builder, against the independent parser ---------------------------------------


@pytest.mark.parametrize("name", ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"])
def test_a_protocol_probe_offers_exactly_that_version(name):
    protocol = PROTOCOLS[name]
    hello = _parse(tls_probe.protocol_hello(protocol, "scanner.example"))
    assert hello.client_version == protocol.version
    assert hello.record_version == (SSL3 if name == "SSLv3" else TLS10)
    assert hello.suites[:-1] == list(protocol.probe_suites) and hello.suites[-1] == SCSV
    assert hello.compression == b"\x00" and hello.session_id == b""
    assert hello.supported_versions is None  # only a TLS 1.3 offer carries that extension
    assert len(hello.random) == 32 and hello.random != bytes(32)


def test_sslv3_carries_no_extensions_because_it_defines_none():
    assert _parse(tls_probe.protocol_hello(PROTOCOLS["SSLv3"], "scanner.example")).extensions == {}


@pytest.mark.parametrize("name", ["TLSv1", "TLSv1.1"])
def test_old_tls_gets_a_name_and_curves_but_no_signature_algorithms(name):
    hello = _parse(tls_probe.protocol_hello(PROTOCOLS[name], "scanner.example"))
    assert hello.sni == "scanner.example"
    assert hello.supported_groups and hello.signature_algorithms is None


def test_tls12_also_offers_signature_algorithms():
    hello = _parse(tls_probe.protocol_hello(PROTOCOLS["TLSv1.2"], "scanner.example"))
    assert hello.sni == "scanner.example" and hello.supported_groups and hello.signature_algorithms


def test_tls13_is_offered_through_supported_versions_with_a_key_share():
    hello = _parse(tls_probe.protocol_hello(PROTOCOLS["TLSv1.3"], "scanner.example"))
    assert hello.client_version == TLS12  # the legacy field; 1.3 is in the extension
    assert hello.supported_versions == [TLS13]
    assert hello.suites == list(PROTOCOLS["TLSv1.3"].probe_suites)
    assert [(group, len(key)) for group, key in hello.key_shares] == [(0x001D, 32)]
    assert len(hello.session_id) == 32  # middlebox-compatibility mode, as real clients send it
    assert hello.signature_algorithms


@pytest.mark.parametrize("group", [g for g in RULES.groups if g.suites], ids=lambda g: g.id)
def test_a_group_probe_offers_only_that_groups_suites(group):
    hello = _parse(tls_probe.group_hello(group, "scanner.example"))
    assert hello.client_version == TLS12  # so a server may answer with any version up to 1.2
    assert hello.suites == [s.code for s in group.suites] + [SCSV]
    assert hello.supported_versions is None and hello.signature_algorithms


@pytest.mark.parametrize(
    "host, expected",
    [
        ("scanner.example", "scanner.example"),
        ("Scanner.Example", "scanner.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("127.0.0.1", None),
        ("::1", None),
        ("2001:db8::1", None),
    ],
)
def test_the_server_name_is_sent_for_names_and_never_for_addresses(host, expected):
    hello = _parse(tls_probe.protocol_hello(PROTOCOLS["TLSv1.2"], host))
    assert hello.sni == expected
    assert (EXT_SERVER_NAME in hello.extensions) is (expected is not None)


def test_every_hello_has_fresh_randomness_unless_told_otherwise():
    first = _parse(tls_probe.protocol_hello(PROTOCOLS["TLSv1.2"], "h.example"))
    second = _parse(tls_probe.protocol_hello(PROTOCOLS["TLSv1.2"], "h.example"))
    assert first.random != second.random
    fixed = b"\x07" * 32
    assert _parse(tls_probe.protocol_hello(PROTOCOLS["TLSv1.2"], "h.example", random_bytes=fixed)).random == fixed


# --- reading the first reply -----------------------------------------------------------------------


def _reply(data: bytes, *, close: bool = True, trickle: bool = False, timeout: float = 2) -> tls_probe.ProbeResult:
    """Feed ``data`` to read_reply() over a socket pair, the way a server's answer would arrive."""
    reader, writer = socket.socketpair()

    def send():
        if trickle:
            for i in range(len(data)):
                writer.sendall(data[i : i + 1])
                threading.Event().wait(0.002)
        else:
            writer.sendall(data)
        if close:
            writer.close()

    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    reader.settimeout(timeout)
    try:
        return tls_probe.read_reply(reader)
    finally:
        thread.join(5)
        reader.close()
        if not close:
            writer.close()


@pytest.mark.parametrize(
    "version, name",
    [(SSL3, "SSLv3"), (TLS10, "TLSv1"), (TLS11, "TLSv1.1"), (TLS12, "TLSv1.2")],
)
def test_a_server_hello_names_the_protocol_and_the_suite(version, name):
    result = _reply(server_hello(version, 0xC02F))
    assert (result.outcome, result.protocol, result.suite) == (Outcome.ACCEPTED, name, 0xC02F)


def test_tls13_is_recognised_by_its_extension_not_the_legacy_version():
    result = _reply(server_hello(TLS12, 0x1301, tls13=True))
    assert (result.outcome, result.protocol, result.suite) == (Outcome.ACCEPTED, "TLSv1.3", 0x1301)


def test_a_hello_retry_request_still_means_tls13_is_enabled():
    result = _reply(server_hello(TLS12, 0x1301, tls13=True, random=HELLO_RETRY_REQUEST_RANDOM))
    assert (result.outcome, result.protocol) == (Outcome.ACCEPTED, "TLSv1.3")


def test_a_reply_arriving_one_byte_at_a_time_is_read():
    assert _reply(server_hello(TLS12, 0xC02F), trickle=True).protocol == "TLSv1.2"


def test_a_server_hello_split_over_two_records_is_read():
    whole = server_hello(TLS12, 0xC02F)
    payload = whole[5:]
    first, second = payload[:20], payload[20:]
    records = (
        b"\x16\x03\x03"
        + len(first).to_bytes(2, "big")
        + first
        + b"\x16\x03\x03"
        + len(second).to_bytes(2, "big")
        + second
    )
    assert _reply(records).protocol == "TLSv1.2"


@pytest.mark.parametrize(
    "description, name", [(70, "protocol_version"), (40, "handshake_failure"), (71, "insufficient_security")]
)
def test_a_fatal_alert_means_not_accepted_and_says_which(description, name):
    result = _reply(alert(TLS12, description))
    assert result.outcome is Outcome.REJECTED and name in result.detail


def test_closing_without_a_reply_means_not_accepted():
    result = _reply(b"")
    assert result.outcome is Outcome.REJECTED and "closed" in result.detail


def test_a_reply_that_is_not_tls_is_an_error_not_a_rejection():
    result = _reply(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    assert result.outcome is Outcome.ERROR and "not a TLS" in result.detail


def test_silence_is_an_error_not_a_rejection():
    result = _reply(b"", close=False, timeout=0.3)
    assert result.outcome is Outcome.ERROR and "no reply" in result.detail


@pytest.mark.parametrize(
    "data, fragment",
    [
        (b"\x16\x03\x03\xff\xff" + b"\x00" * 16, "length"),  # a record longer than TLS allows
        (server_hello(TLS12, 0xC02F)[:20], "truncated"),  # cut short, then closed
        (b"\x16\x03\x03\x00\x04\x0b\x00\x00\x00", "unexpected"),  # a Certificate where a ServerHello belongs
    ],
)
def test_a_malformed_reply_is_an_error_with_a_reason(data, fragment):
    result = _reply(data)
    assert result.outcome is Outcome.ERROR and fragment in result.detail


# --- the probe run, against the fake server --------------------------------------------------------


def _run(server, hostname="127.0.0.1", rules=RULES, timeout=2, **kwargs):
    kwargs = {**NO_PAUSE, **kwargs}
    return tls_probe.run_probes(hostname, server.port, timeout, rules, **kwargs)


def test_it_finds_exactly_the_versions_a_server_has_enabled(fake_tls):
    server = fake_tls(Policy(versions={TLS10, TLS12}))
    report = _run(server)
    outcomes = {name: r.outcome for name, r in report.protocols.items()}
    assert outcomes == {
        "SSLv3": Outcome.REJECTED,
        "TLSv1": Outcome.ACCEPTED,
        "TLSv1.1": Outcome.REJECTED,  # the server answered a 1.1 hello with 1.0: 1.1 itself is not enabled
        "TLSv1.2": Outcome.ACCEPTED,
        "TLSv1.3": Outcome.REJECTED,
    }
    assert "TLSv1" in report.protocols["TLSv1.1"].detail


def test_it_finds_exactly_the_weak_groups_a_server_accepts(fake_tls):
    server = fake_tls(Policy(versions={TLS10, TLS12}, suites={0x0005, 0x000A}))  # RC4_128_SHA and 3DES_EDE_CBC_SHA
    report = _run(server)
    accepted = {gid for gid, r in report.groups.items() if r.outcome is Outcome.ACCEPTED}
    assert accepted == {"RC4", "3DES"}
    assert report.groups["RC4"].suite == 0x0005 and report.groups["3DES"].suite == 0x000A
    assert [gid for gid in report.groups] == ["NULL", "EXPORT", "ANON", "RC4", "3DES", "DES"]  # rule order


def test_tls13_only_server_is_recognised(fake_tls):
    report = _run(fake_tls(Policy(versions={TLS13})))
    assert report.protocols["TLSv1.3"].outcome is Outcome.ACCEPTED
    assert not [n for n in ("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2") if report.protocols[n].outcome is Outcome.ACCEPTED]


def test_a_run_opens_one_connection_per_probe_and_sends_one_record_on_each(fake_tls):
    server = fake_tls(Policy(versions={TLS12}))
    report = _run(server)
    assert report.connections == PROBES == server.connections == len(server.hellos)
    assert server.errors == [], "the strict parser accepted every ClientHello the scanner sent"
    assert server.extra_bytes == [], "nothing may follow the ClientHello: no handshake, no application data"
    assert len({h.random for h in server.hellos}) == PROBES, "every probe uses fresh randomness"


def test_the_server_name_goes_out_for_a_hostname(fake_tls):
    server = fake_tls(Policy(versions={TLS12}))

    def connect(host, port, timeout):  # a name that resolves nowhere, reached through the loopback address
        return socket.create_connection(("127.0.0.1", port), timeout=timeout)

    _run(server, hostname="scanner.example", connect=connect)
    named = {h.sni for h in server.hellos if h.client_version != SSL3}
    assert named == {"scanner.example"}
    assert [h.sni for h in server.hellos if h.client_version == SSL3] == [None], "SSLv3 defines no extensions"


def test_a_connection_budget_stops_the_run_and_says_what_was_not_tested(fake_tls):
    server = fake_tls(Policy(versions={TLS12}))
    tight = dataclasses.replace(RULES, max_connections=5)  # two are kept for the certificate checks
    report = _run(server, rules=tight)
    assert server.connections == report.connections == 3
    untested = [r for r in (*report.protocols.values(), *report.groups.values()) if r.outcome is Outcome.ERROR]
    assert len(untested) == PROBES - 3 and all("connection budget" in r.detail for r in untested)


def test_probes_are_spaced_by_the_declared_pause(fake_tls):
    server = fake_tls(Policy(versions={TLS12}))
    slept: list[float] = []
    _run(server, sleep=slept.append)
    assert slept == [RULES.pause_seconds] * (PROBES - 1)


def test_every_probe_counts_against_the_limiter(fake_tls):
    server = fake_tls(Policy(versions={TLS12}))
    calls: list[str] = []

    class Counting:
        def acquire(self, url):
            calls.append(url)

    _run(server, limiter=Counting())
    assert calls == [f"https://127.0.0.1:{server.port}/"] * PROBES


def test_max_requests_stops_the_probes_instead_of_being_swallowed(fake_tls):
    server = fake_tls(Policy(versions={TLS12}))
    with pytest.raises(ScanLimitReached):
        _run(server, limiter=ScanLimiter(max_requests=3))
    assert server.connections == 3


def test_the_connection_function_can_be_replaced_so_a_proxy_can_be_used(fake_tls):
    server = fake_tls(Policy(versions={TLS12}))
    seen: list[tuple] = []

    def connect(host, port, timeout):
        seen.append((host, port))
        return socket.create_connection((host, port), timeout=timeout)

    _run(server, connect=connect)
    assert seen == [("127.0.0.1", server.port)] * PROBES


def test_a_suite_the_probe_never_offered_is_not_taken_as_acceptance(fake_tls):
    # A server (or a middlebox) that answers with a suite outside the group would otherwise be reported
    # as accepting that group: the verdict has to check the suite against what was offered.
    server = fake_tls(Policy(versions={TLS12}, force_suite=0xC02F))  # an AES-GCM suite, offered to no weak group
    report = _run(server)
    for group_id, result in report.groups.items():
        assert result.outcome is Outcome.ERROR and "not offered" in result.detail, group_id
    assert all(r.outcome is Outcome.ACCEPTED for n, r in report.protocols.items() if n == "TLSv1.2")


ONE_PROBE = dataclasses.replace(RULES, protocols=RULES.protocols[3:4], groups=())  # a single TLS 1.2 probe


@pytest.mark.parametrize("behaviour", ["close", "reset"])
def test_a_server_that_hangs_up_has_not_accepted(fake_tls, behaviour):
    report = _run(fake_tls(Policy(behaviour=behaviour)), rules=ONE_PROBE)
    assert report.protocols["TLSv1.2"].outcome is Outcome.REJECTED


def test_a_server_that_never_answers_could_not_be_tested(fake_tls):
    report = _run(fake_tls(Policy(behaviour="silent")), rules=ONE_PROBE, timeout=0.3)
    assert report.protocols["TLSv1.2"].outcome is Outcome.ERROR


def test_a_plain_http_server_could_not_be_tested(fake_tls):
    assert _run(fake_tls(Policy(behaviour="http")), rules=ONE_PROBE).protocols["TLSv1.2"].outcome is Outcome.ERROR


def test_a_server_answering_in_small_pieces_is_still_read(fake_tls):
    report = _run(fake_tls(Policy(versions={TLS12}, behaviour="split")), rules=ONE_PROBE)
    assert report.protocols["TLSv1.2"].outcome is Outcome.ACCEPTED


def test_an_unreachable_host_stops_after_the_first_failure(closed_port):
    attempts: list[int] = []

    def connect(host, port, timeout):
        attempts.append(port)
        return socket.create_connection((host, port), timeout=timeout)

    report = tls_probe.run_probes("127.0.0.1", closed_port, 2, RULES, connect=connect, **NO_PAUSE)
    assert len(attempts) == 1, "ten more probes would each wait out the timeout"
    results = [*report.protocols.values(), *report.groups.values()]
    assert len(results) == PROBES and all(r.outcome is Outcome.ERROR for r in results)
    assert all(r.detail for r in results)


def test_one_slow_probe_is_capped_by_the_probe_timeout(fake_tls):
    capped = dataclasses.replace(ONE_PROBE, probe_timeout_seconds=0.3)
    server = fake_tls(Policy(behaviour="silent"))
    before = time.monotonic()
    report = _run(server, rules=capped, timeout=30)  # the scan timeout is 30 s, the probe's cap is 0.3 s
    assert time.monotonic() - before < 5
    assert report.protocols["TLSv1.2"].outcome is Outcome.ERROR


# --- against real OpenSSL ------------------------------------------------------------------------


def test_the_parser_reads_a_real_openssl_client_hello(fake_tls):
    server = fake_tls(Policy(behaviour="close"))
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", server.port), timeout=3) as sock:
        ctx.wrap_socket(sock, server_hostname="scanner.example")
    hello = server.hellos[0]
    assert server.errors == [] and hello.sni == "scanner.example"
    assert TLS12 in (hello.supported_versions or []) and hello.suites and hello.signature_algorithms


def _probe_real(https_server, protocol_name, only_version=None):
    _, port = https_server(QuietHandler, cert="valid", only_version=only_version)
    probe = RULES.protocols[[p.name for p in RULES.protocols].index(protocol_name)]
    single = dataclasses.replace(RULES, protocols=(probe,), groups=())
    return tls_probe.run_probes("127.0.0.1", port, 5, single, **NO_PAUSE).protocols[protocol_name]


def test_a_real_server_answers_our_tls12_hello(https_server):
    result = _probe_real(https_server, "TLSv1.2")
    assert result.outcome is Outcome.ACCEPTED and result.protocol == "TLSv1.2"


@pytest.mark.skipif(not ssl.HAS_TLSv1_3, reason="this OpenSSL has no TLS 1.3")
def test_a_real_server_answers_our_tls13_hello(https_server):
    result = _probe_real(https_server, "TLSv1.3")
    assert result.outcome is Outcome.ACCEPTED and result.protocol == "TLSv1.3"


def test_a_modern_real_server_has_none_of_the_weak_versions_or_groups(https_server):
    _, port = https_server(QuietHandler, cert="valid")
    report = tls_probe.run_probes("127.0.0.1", port, 5, RULES, **NO_PAUSE)
    weak = [n for n in ("SSLv3", "TLSv1", "TLSv1.1") if report.protocols[n].outcome is Outcome.ACCEPTED]
    assert weak == [], "a modern server must not be reported as accepting a legacy version"
    assert [g for g, r in report.groups.items() if r.outcome is Outcome.ACCEPTED] == []
    assert not [r for r in (*report.protocols.values(), *report.groups.values()) if r.outcome is Outcome.ERROR]


def test_a_real_tls10_only_server_is_detected(https_server):
    result = _probe_real(https_server, "TLSv1", only_version=ssl.TLSVersion.TLSv1)
    assert result.outcome is Outcome.ACCEPTED and result.protocol == "TLSv1"
