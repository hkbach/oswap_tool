"""FR-CI-07: --proxy, --header, --cookie, --user-agent, --version, --quiet/--verbose.

Credentials passed on the command line must never reach a report or a log, even when the
target reflects them back; and the scanner must still identify itself (NFR-SEC-03).
"""

from __future__ import annotations

import json

import pytest
from conftest import QuietHandler
from mock_proxy import ProxyHandler, start_proxy

from websec_scanner import __version__, cli
from websec_scanner.http_utils import USER_AGENT
from websec_scanner.request_options import is_sensitive_header, parse_cookie, parse_header

TOKEN = "fake-bearer-token-0123456789"  # noqa: S105 - a fake credential the tests check never leaks
SESSION = "fake-session-cookie-abcdef"


class Reflecting(QuietHandler):
    """Echoes request headers back in a header the scanner reports as evidence (HDR-INFO-X-POWERED-BY)."""

    received: list[dict] = []

    def do_GET(self):
        type(self).received.append(dict(self.headers))
        echoed = f"{self.headers.get('Authorization', '')} {self.headers.get('Cookie', '')}".strip()
        self.send(200, b"home", [("X-Powered-By", echoed or "none")])


@pytest.fixture
def reflecting(http_server):
    Reflecting.received = []
    return http_server(Reflecting)


def _run(argv, capsys) -> tuple[int, str, str]:
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


# --- parsing ---------------------------------------------------------------------


def test_header_and_cookie_parsing():
    assert parse_header("X-Env: staging") == ("X-Env", "staging")
    assert parse_header("Authorization:Bearer x") == ("Authorization", "Bearer x")
    assert parse_cookie("session=abc") == ("session", "abc")


@pytest.mark.parametrize(
    "bad",
    ["no-colon-here", ": empty-name", "Bad Name: x", "X-Ok: line\r\nInjected: 1", "X-Ok: tab\x00null"],
)
def test_a_malformed_or_injecting_header_is_rejected(bad):
    with pytest.raises(ValueError):
        parse_header(bad)


@pytest.mark.parametrize("bad", ["noequals", "=novalue-name", "a b=c", "s=line\r\nX: 1"])
def test_a_malformed_cookie_is_rejected(bad):
    with pytest.raises(ValueError):
        parse_cookie(bad)


@pytest.mark.parametrize(
    "name, sensitive",
    [
        ("Authorization", True),
        ("Proxy-Authorization", True),
        ("Cookie", True),
        ("X-Api-Key", True),
        ("X-Auth-Token", True),
        ("X-Session-Id", True),
        ("X-Client-Secret", True),
        ("X-Env", False),
        ("Accept-Language", False),
        ("X-Request-Source", False),
    ],
)
def test_which_headers_carry_credentials(name, sensitive):
    assert is_sensitive_header(name) is sensitive


# --- --header / --cookie -----------------------------------------------------------


def test_custom_headers_and_cookies_reach_the_target(reflecting, capsys):
    _run([reflecting, "--yes", "--no-color", "--header", "X-Env: staging", "--cookie", f"session={SESSION}",
          "--checks", "headers"], capsys)  # fmt: skip
    first = Reflecting.received[0]
    assert first["X-Env"] == "staging"
    assert f"session={SESSION}" in first["Cookie"]


@pytest.mark.parametrize("fmt", ["json", "sarif", "html", "csv", "junit"])
def test_a_reflected_credential_never_reaches_any_report(reflecting, tmp_path, capsys, fmt):
    out = tmp_path / f"report.{fmt}"
    code, console, err = _run(
        [reflecting, "--yes", "--no-color", "--header", f"Authorization: Bearer {TOKEN}",
         "--cookie", f"session={SESSION}", f"--{fmt}", str(out)],
        capsys,
    )  # fmt: skip
    assert Reflecting.received[0]["Authorization"] == f"Bearer {TOKEN}"  # it was really sent
    text = out.read_text(encoding="utf-8")
    for secret in (TOKEN, SESSION):
        assert secret not in text, f"{secret} leaked into the {fmt} report"
        assert secret not in console and secret not in err


def test_a_harmless_header_value_is_not_masked(http_server, tmp_path, capsys):
    # Masking every value would mangle the report: "staging" also appears in hostnames.
    class Echo(QuietHandler):
        def do_GET(self):
            self.send(200, b"x", [("X-Powered-By", f"env={self.headers.get('X-Env')}")])

    out = tmp_path / "r.json"
    _run([http_server(Echo), "--yes", "--no-color", "--header", "X-Env: staging", "--json", str(out)], capsys)
    assert "env=staging" in out.read_text(encoding="utf-8")


def test_an_injected_header_on_the_command_line_fails_before_any_request(reflecting, capsys):
    with pytest.raises(SystemExit):
        cli.main([reflecting, "--yes", "--header", "X-A: 1\r\nX-Injected: 2"])
    assert Reflecting.received == []


# --- --user-agent ------------------------------------------------------------------


def test_user_agent_is_a_prefix_and_the_scanner_still_identifies_itself(reflecting, capsys):
    _run([reflecting, "--yes", "--no-color", "--user-agent", "AcmeCI/2", "--checks", "headers"], capsys)
    ua = Reflecting.received[0]["User-Agent"]
    assert ua == f"AcmeCI/2 {USER_AGENT}"  # NFR-SEC-03: never replaced, only extended


def test_a_user_agent_cannot_inject_headers(reflecting):
    with pytest.raises(SystemExit):
        cli.main([reflecting, "--yes", "--user-agent", "x\r\nX-Injected: 1"])
    assert Reflecting.received == []


# --- --proxy -----------------------------------------------------------------------


def test_http_requests_go_through_the_proxy(http_server, capsys):
    proxy, proxy_url = start_proxy()
    try:
        target = http_server(Reflecting)
        _run([target, "--yes", "--no-color", "--proxy", proxy_url, "--checks", "headers,exposed-files"], capsys)
    finally:
        proxy.shutdown()
    methods = {m for m, _ in ProxyHandler.seen}
    assert "GET" in methods
    assert all(t.startswith(target.rstrip("/")) for m, t in ProxyHandler.seen if m == "GET")


def test_the_tls_check_tunnels_through_the_proxy_too(https_server, capsys):
    # The TLS check opens its own sockets; with --proxy it must CONNECT through it, not go direct.
    url, port = https_server(QuietHandler)
    proxy, proxy_url = start_proxy()
    try:
        result = cli.run_scan(url, groups=["tls"], proxy=proxy_url)
    finally:
        proxy.shutdown()
    connects = [t for m, t in ProxyHandler.seen if m == "CONNECT"]
    assert f"127.0.0.1:{port}" in connects
    assert "tls" in result.checks_run
    # The baseline GET fails on the self-signed certificate (expected); the TLS check must not.
    assert not [e for e in result.errors if e.startswith("Check 'tls' failed")], result.errors
    assert any(f.id == "TLS-CERT-NOT-TRUSTED" for f in result.findings)  # it measured the real server


def test_proxy_credentials_are_sent_and_never_reported(http_server, tmp_path, capsys):
    proxy, proxy_url = start_proxy()
    authed = proxy_url.replace("http://", "http://scanuser:fake-proxy-pass@")
    out = tmp_path / "r.json"
    try:
        code, console, err = _run(
            [http_server(Reflecting), "--yes", "--no-color", "--proxy", authed, "--json", str(out),
             "--checks", "headers"],
            capsys,
        )  # fmt: skip
    finally:
        proxy.shutdown()
    assert any(a and a.startswith("Basic ") for a in ProxyHandler.proxy_auth)
    for text in (out.read_text(encoding="utf-8"), console, err):
        assert "fake-proxy-pass" not in text


@pytest.mark.parametrize("bad", ["https://proxy.example:3128", "socks5://proxy.example:1080", "proxy.example:3128"])
def test_only_http_proxies_are_accepted(bad, capsys):
    with pytest.raises(SystemExit):
        cli.main(["http://127.0.0.1:1/", "--yes", "--proxy", bad])
    assert "--proxy" in capsys.readouterr().err


# --- --version, --quiet, --verbose ----------------------------------------------------


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_quiet_prints_one_line_and_keeps_the_exit_code(reflecting, capsys):
    code, out, _ = _run([reflecting, "--yes", "--no-color", "--quiet"], capsys)
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1, out
    assert "findings" in lines[0] and reflecting.rstrip("/") in lines[0]
    loud, _, _ = _run([reflecting, "--yes", "--no-color"], capsys)
    assert code == loud


def test_verbose_logs_each_request_without_credentials(reflecting, capsys):
    _, _, err = _run(
        [reflecting, "--yes", "--no-color", "--verbose", "--header", f"Authorization: Bearer {TOKEN}",
         "--checks", "headers"],
        capsys,
    )  # fmt: skip
    request_lines = [line for line in err.splitlines() if line.startswith("[request]")]
    assert request_lines and "GET" in request_lines[0] and "200" in request_lines[0]
    assert TOKEN not in err


def test_quiet_and_verbose_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit):
        cli.main(["http://127.0.0.1:1/", "--yes", "--quiet", "--verbose"])


def test_json_unaffected_by_quiet(reflecting, tmp_path, capsys):
    out = tmp_path / "r.json"
    _run([reflecting, "--yes", "--no-color", "--quiet", "--json", str(out)], capsys)
    assert json.loads(out.read_text(encoding="utf-8"))["findings"]


def test_quiet_still_says_why_a_scan_could_not_complete(closed_port, capsys):
    # Exit 3 with no reason is useless in a CI log: the errors go to stderr, stdout stays one line.
    code, out, err = _run(
        [f"http://127.0.0.1:{closed_port}/", "--yes", "--no-color", "--quiet", "--timeout", "2"], capsys
    )
    assert code == 3
    assert len([line for line in out.splitlines() if line.strip()]) == 1
    assert "Could not fetch" in err
