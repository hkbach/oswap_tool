"""FR-AUTH-02 / D2: secrets are redacted by default in every output."""

from __future__ import annotations

import json
import threading

import pytest
import requests
from conftest import QuietHandler

from websec_scanner import cli, output, redact, web

COOKIE_SECRET = "SeSsIoN-VaLuE-0123456789"  # noqa: S105 - fake value the leak tests search for
TOKEN_SECRET = "Tok3n-Secret-9876"  # noqa: S105 - fake value the leak tests search for
SECRETS = (COOKIE_SECRET, TOKEN_SECRET)


class SecretHandler(QuietHandler):
    """Sets a session cookie; every other path is a plain 404."""

    def do_GET(self):
        if self.path.split("?")[0] == "/":
            self.send(200, b"home", [("Set-Cookie", f"session={COOKIE_SECRET}; Path=/; Max-Age=100")])
        else:
            self.send(404)


def _target(http_server) -> str:
    return http_server(SecretHandler) + f"?access_token={TOKEN_SECRET}"


def _assert_no_secrets(text: str, where: str) -> None:
    for secret in SECRETS:
        assert secret not in text, f"secret leaked in {where}"


# --- the redaction primitives ------------------------------------------------------


def test_cookie_value_is_masked_but_name_and_attributes_stay():
    raw = "session=abc123; Path=/; Max-Age=100; HttpOnly"
    pair = redact.cookie_redaction(raw)
    assert redact.redact(raw, [pair]) == "session=<redacted len=6>; Path=/; Max-Age=100; HttpOnly"


def test_short_cookie_values_do_not_mangle_other_text():
    raw = "s=1; Max-Age=100; Path=/v1"
    assert redact.redact(raw, [redact.cookie_redaction(raw)]) == "s=<redacted len=1>; Max-Age=100; Path=/v1"


@pytest.mark.parametrize(
    "text, expected",
    [
        ("https://a.example/?token=abc&x=1", "https://a.example/?token=<redacted len=3>&x=1"),
        (
            "https://a.example/p?API_KEY=k1&sessionid=s2",
            "https://a.example/p?API_KEY=<redacted len=2>&sessionid=<redacted len=2>",
        ),
        ("GET /cb?code=1&sig=zz#frag", "GET /cb?code=1&sig=<redacted len=2>#frag"),
        ("https://a.example/?page=2&sort=asc", "https://a.example/?page=2&sort=asc"),
        (
            "url: /x?token=abc, then /y?key=k1: failed",
            "url: /x?token=<redacted len=3>, then /y?key=<redacted len=2>: failed",
        ),
    ],
)
def test_sensitive_url_parameters_are_masked(text, expected):
    assert redact.redact(text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("https://admin:pw12@t.example/", "https://<redacted len=5>:<redacted len=4>@t.example/"),
        ("Could not fetch http://tok3n@t.example:8443/x", "Could not fetch http://<redacted len=5>@t.example:8443/x"),
        ("https://u:@t.example/", "https://<redacted len=1>:@t.example/"),
        ("https://t.example/@user and mailto:a@b.example", "https://t.example/@user and mailto:a@b.example"),
    ],
)
def test_credentials_in_urls_are_masked(text, expected):
    assert redact.redact(text) == expected


# --- no secret survives any output ----------------------------------------------------


def test_cli_console_and_json_are_redacted(http_server, tmp_path, capsys):
    out = tmp_path / "report.json"
    cli.main([_target(http_server), "--yes", "--no-color", "--json", str(out)])
    captured = capsys.readouterr()
    _assert_no_secrets(captured.out + captured.err, "console")
    text = out.read_text(encoding="utf-8")
    _assert_no_secrets(text, "--json")
    report = json.loads(text)
    assert report["secrets_redacted"] is True
    (cookie,) = [f for f in report["findings"] if f["id"] == "COOKIE-FLAGS-MISSING"]
    assert cookie["evidence"] == f"session=<redacted len={len(COOKIE_SECRET)}>; Path=/; Max-Age=100"


def test_show_secrets_is_explicit_and_warns(http_server, tmp_path, capsys):
    out = tmp_path / "report.json"
    cli.main([_target(http_server), "--yes", "--no-color", "--show-secrets", "--json", str(out)])
    assert "--show-secrets" in capsys.readouterr().err
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["secrets_redacted"] is False
    assert COOKIE_SECRET in out.read_text(encoding="utf-8")


def test_html_report_warns_when_secrets_are_shown(http_server):
    from websec_scanner.html_report import render_html

    result = cli.run_scan(_target(http_server))
    assert "not redacted" not in render_html(output.build_report(result))
    assert "not redacted" in render_html(output.build_report(result, show_secrets=True))


def test_web_ui_always_redacts_even_if_asked_not_to(http_server):
    server = web.build_server("127.0.0.1", 0, timeout=5)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    ui = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        payload = {"target": _target(http_server), "authorized": True, "show_secrets": True, "showSecrets": True}
        resp = requests.post(f"{ui}/api/scan", json=payload, timeout=60)
        _assert_no_secrets(resp.text, "web JSON")
        assert resp.json()["secrets_redacted"] is True
        html = requests.get(ui + resp.json()["report_url"], timeout=5).text
        _assert_no_secrets(html, "web HTML report")
    finally:
        server.shutdown()
        server.server_close()


def test_same_cookie_on_a_redirect_and_the_final_response_is_redacted_in_both(http_server):
    # Two COOKIE-FLAGS-MISSING findings with the same fingerprint (same cookie name, same
    # target): the redactions of both must apply, not only those of the last one.
    first, second = f"{COOKIE_SECRET}-hop", f"{COOKIE_SECRET}-final"

    class RedirectThenHome(QuietHandler):
        def do_GET(self):
            if self.path == "/":
                self.send(302, b"", [("Location", "/home"), ("Set-Cookie", f"sid={first}; Path=/")])
            elif self.path == "/home":
                self.send(200, b"home", [("Set-Cookie", f"sid={second}; Path=/")])
            else:
                self.send(404)

    report = output.build_report(cli.run_scan(http_server(RedirectThenHome), timeout=5))
    text = json.dumps(report)
    assert first not in text and second not in text
    evidence = sorted(f["evidence"] for f in report["findings"] if f["id"] == "COOKIE-FLAGS-MISSING")
    assert evidence == [f"sid=<redacted len={len(first)}>; Path=/", f"sid=<redacted len={len(second)}>; Path=/"]


def test_credentials_in_the_target_url_never_reach_the_reports(http_server, tmp_path, capsys):
    user, password = "scan-user", f"{COOKIE_SECRET}-pw"
    target = http_server(SecretHandler).replace("http://", f"http://{user}:{password}@")
    outs = {k: tmp_path / f"r.{k}" for k in ("json", "sarif", "html")}
    cli.main([target, "--yes", "--no-color", *[a for k, p in outs.items() for a in (f"--{k}", str(p))]])
    captured = capsys.readouterr()
    texts = {"console": captured.out + captured.err, **{k: p.read_text("utf-8") for k, p in outs.items()}}
    for where, text in texts.items():
        assert password not in text and user not in text, f"credentials leaked in {where}"
    report = json.loads(outs["json"].read_text(encoding="utf-8"))
    assert report["target"].startswith(f"http://<redacted len={len(user)}>:<redacted len={len(password)}>@127.0.0.1:")
    assert "redacted" not in web._report_filename(report)


def test_errors_are_redacted(closed_port):
    result = cli.run_scan(f"http://127.0.0.1:{closed_port}/?token={TOKEN_SECRET}", timeout=2)
    assert TOKEN_SECRET in result.errors[0]  # raw result keeps it; output must not
    report = output.build_report(result)
    _assert_no_secrets(json.dumps(report), "errors")
