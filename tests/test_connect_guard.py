"""The optional connect guard of the scanning core (decision D12): every connection, HTTP and TLS, is checked once it
is made and before anything is sent. It is how the hosted service keeps scans away from internal addresses; without a
guard nothing changes, which the rest of the suite proves.
"""

from __future__ import annotations

import socket

import pytest
import requests
from conftest import QuietHandler
from crawl_site import Page, html, site_handler

from websec_scanner import cli
from websec_scanner.checks import tls_check
from websec_scanner.http_utils import ConnectBlocked, build_session, check_peer


class Recorder:
    """A guard that remembers what it was asked and answers as told."""

    def __init__(self, allow: bool = True) -> None:
        self.allow, self.asked = allow, []

    def __call__(self, ip: str) -> bool:
        self.asked.append(ip)
        return self.allow


# --- check_peer -----------------------------------------------------------------------------------


@pytest.fixture
def connected_pair():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.create_connection(server.getsockname())
    yield client
    client.close()
    server.close()


def test_no_guard_returns_the_socket_untouched(connected_pair):
    assert check_peer(connected_pair, None) is connected_pair


def test_an_allowed_peer_is_asked_about_by_its_address_only(connected_pair):
    guard = Recorder(True)
    assert check_peer(connected_pair, guard) is connected_pair
    assert guard.asked == ["127.0.0.1"]  # an address, not "127.0.0.1:port" and not a tuple


def test_a_refused_peer_closes_the_socket_and_raises_without_naming_the_address(connected_pair):
    with pytest.raises(ConnectBlocked) as raised:
        check_peer(connected_pair, Recorder(False))
    assert "127.0.0.1" not in str(raised.value) and isinstance(raised.value, OSError)
    assert connected_pair.fileno() == -1  # closed


def test_an_ipv6_scope_id_is_not_part_of_the_address():
    class FakeSocket:
        closed = False

        def getpeername(self):
            return ("fe80::1%12", 80, 0, 12)

        def close(self):
            self.closed = True

    guard = Recorder(True)
    check_peer(FakeSocket(), guard)
    assert guard.asked == ["fe80::1"]


def test_a_socket_that_is_not_connected_is_closed_and_the_error_passes_on():
    sock = socket.socket()
    with pytest.raises(OSError):
        check_peer(sock, Recorder(True))
    assert sock.fileno() == -1


# --- the HTTP session -----------------------------------------------------------------------------


def test_a_session_without_a_guard_connects_as_before(http_server):
    handler = site_handler({"/": Page(html())})
    base = http_server(handler)
    assert build_session().get(base, timeout=5).status_code == 200
    assert handler.hits == ["/"]


def test_a_guard_that_allows_lets_the_request_through_and_is_asked_once_per_connection(http_server):
    handler = site_handler({"/": Page(html()), "/a": Page(html())})
    base = http_server(handler)
    guard = Recorder(True)
    session = build_session(connect_guard=guard)
    assert session.get(base, timeout=5).status_code == 200
    assert session.get(base + "a", timeout=5).status_code == 200
    assert (
        guard.asked and set(guard.asked) == {"127.0.0.1"} and len(guard.asked) <= 2
    )  # a kept-alive connection is reused


def test_a_guard_that_refuses_stops_the_request_before_a_single_byte_is_sent(http_server):
    handler = site_handler({"/": Page(html())})
    base = http_server(handler)
    guard = Recorder(False)
    with pytest.raises(requests.exceptions.ConnectionError):
        build_session(connect_guard=guard).get(base, timeout=5)
    assert guard.asked and handler.hits == []  # the server never saw a request


def test_the_guard_is_asked_again_for_a_redirect_to_another_address(http_server):
    """Allow the first connection and refuse the next: a redirect cannot lead somewhere the guard would refuse."""
    seen = []

    class Redirect(QuietHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send(302, b"", {"Location": f"http://localhost:{self.server.server_address[1]}/next"})

    base = http_server(Redirect)
    asked = []

    def guard(ip):  # the first connection is allowed; urllib3 retries a refused one, so later calls are refused too
        asked.append(ip)
        return len(asked) == 1

    session = build_session(connect_guard=guard)
    session.max_redirects = 3
    with pytest.raises(requests.exceptions.ConnectionError):
        session.get(base, timeout=5)
    assert seen == ["/"] and len(asked) >= 2  # the redirect led to a second connection, which was refused


def test_a_new_connection_is_checked_even_when_the_name_resolves_differently_later(http_server):
    """The check reads the address the socket really reached, not what a name said earlier (DNS rebinding)."""
    base = http_server(site_handler({"/": Page(html())}))
    port = base.rsplit(":", 1)[1].rstrip("/")
    guard = Recorder(False)
    # "localhost" resolves to a loopback address now; whatever it resolves to, the guard sees the connected address
    with pytest.raises(requests.exceptions.ConnectionError):
        build_session(connect_guard=guard).get(f"http://localhost:{port}/", timeout=5)
    assert guard.asked and all(ip in ("127.0.0.1", "::1") for ip in guard.asked)


# --- the TLS check --------------------------------------------------------------------------------


def test_open_connection_without_a_guard_is_unchanged(http_server):
    base = http_server(site_handler({"/": Page(html())}))
    port = int(base.rsplit(":", 1)[1].rstrip("/"))
    with tls_check._open_connection("127.0.0.1", port, 5) as sock:
        assert sock.getpeername()[0] == "127.0.0.1"


def test_open_connection_with_a_refusing_guard_raises_connect_blocked(http_server):
    base = http_server(site_handler({"/": Page(html())}))
    port = int(base.rsplit(":", 1)[1].rstrip("/"))
    with pytest.raises(ConnectBlocked):
        tls_check._open_connection("127.0.0.1", port, 5, connect_guard=Recorder(False))


class _Quiet(QuietHandler):
    def do_GET(self):
        self.send(200, b"ok")


def test_the_tls_check_makes_no_handshake_to_a_refused_address(https_server):
    _, port = https_server(_Quiet)
    guard = Recorder(False)
    findings = tls_check.check_tls("127.0.0.1", port, timeout=5, connect_guard=guard)
    assert [f.id for f in findings] == ["TLS-CONN-FAILED"]
    assert guard.asked == ["127.0.0.1"]  # one refusal ended the check: no probe, no second connection
    assert "127.0.0.1" not in findings[0].description.split("failed:")[1]  # the reason does not name the address


def test_every_connection_of_the_tls_check_goes_through_the_guard(https_server):
    _, port = https_server(_Quiet)
    guard = Recorder(True)
    tls_check.check_tls("127.0.0.1", port, timeout=5, probe=False, connect_guard=guard)
    assert guard.asked == ["127.0.0.1", "127.0.0.1"]  # the certificate connection and the verifying one


def test_the_probes_connections_go_through_the_guard_too(https_server, monkeypatch):
    """Probes open their own connections; the TLS check hands them the guarded opener."""
    _, port = https_server(_Quiet)
    guard = Recorder(True)
    opened = []
    real = tls_check._open_connection

    def spy(host, tcp_port, seconds, proxy=None, connect_guard=None):
        opened.append(connect_guard)
        return real(host, tcp_port, seconds, proxy, connect_guard)

    monkeypatch.setattr(tls_check, "_open_connection", spy)
    tls_check.check_tls("127.0.0.1", port, timeout=5, probe=True, connect_guard=guard)
    assert len(opened) > 4 and all(g is guard for g in opened)  # certificate, verify and every probe


# --- run_scan -------------------------------------------------------------------------------------


def test_a_scan_with_a_refusing_guard_sends_no_request_and_says_so(http_server):
    handler = site_handler({"/": Page(html())})
    base = http_server(handler)
    result = cli.run_scan(base, connect_guard=Recorder(False), tls_probe=False)
    assert handler.hits == [] and result.baseline_fetched is False and result.findings == []
    assert any("Could not fetch" in error for error in result.errors)


def test_a_scan_with_an_allowing_guard_is_the_same_scan(http_server):
    base = http_server(site_handler({"/": Page(html(), headers={"X-Frame-Options": "DENY"})}))
    plain = cli.run_scan(base, tls_probe=False)
    guard = Recorder(True)
    guarded = cli.run_scan(base, connect_guard=guard, tls_probe=False)
    assert sorted(f.fingerprint for f in guarded.findings) == sorted(f.fingerprint for f in plain.findings)
    assert guard.asked


def test_a_guard_cannot_be_combined_with_a_proxy():
    with pytest.raises(ValueError, match="proxy"):
        cli.run_scan("http://127.0.0.1:1/", connect_guard=Recorder(True), proxy="http://127.0.0.1:3128")


def test_an_https_session_asks_the_guard_before_any_handshake(https_server):
    """The HTTPS pool has its own connection class: the guard must be wired into it, not only into plain HTTP."""
    base, _ = https_server(_Quiet)
    guard = Recorder(False)
    with pytest.raises(requests.exceptions.ConnectionError):
        build_session(connect_guard=guard).get(base, timeout=5)
    assert guard.asked and set(guard.asked) == {
        "127.0.0.1"
    }  # the guard decided; the untrusted certificate never got a say


def test_run_scan_hands_the_guard_to_the_tls_check(https_server, monkeypatch):
    base, _ = https_server(_Quiet)
    guard = Recorder(True)
    seen = []

    def spy(hostname, port=443, **kwargs):
        seen.append(kwargs.get("connect_guard"))
        return []

    monkeypatch.setattr(cli.tls_check, "check_tls", spy)
    cli.run_scan(base, connect_guard=guard, groups=["tls"])
    assert seen == [guard]  # the TLS check opens its own sockets, so it is told about the guard itself
