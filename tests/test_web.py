"""Tests for the local web UI server (websec_scanner.web)."""

from __future__ import annotations

import threading

import pytest
import requests
from mock_server import Handler as MockHandler

from websec_scanner import catalog, output, web
from websec_scanner.models import ScanResult


@pytest.fixture
def ui():
    server = web.build_server("127.0.0.1", 0, timeout=5)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def scan(ui, payload, **kwargs):
    return requests.post(f"{ui}/api/scan", json=payload, timeout=60, **kwargs)


@pytest.mark.parametrize(
    "path, content_type",
    [("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")],
)
def test_static_files_served_with_security_headers(ui, path, content_type):
    resp = requests.get(ui + path, timeout=5)
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith(content_type)
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_unknown_path_is_404(ui):
    assert requests.get(f"{ui}/../SRS.md", timeout=5).status_code == 404
    assert requests.get(f"{ui}/static/app.js", timeout=5).status_code == 404


def test_scan_returns_report(ui, http_server):
    target = http_server(MockHandler)
    resp = scan(ui, {"target": target, "authorized": True})
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == target
    assert data["gate_failed"] is True
    ids = [f["id"] for f in data["findings"]]
    assert "EXPOSURE-ENV" in ids and "COOKIE-FLAGS-MISSING" in ids
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    ranks = [order.index(f["severity"]) for f in data["findings"]]
    assert ranks == sorted(ranks)


def test_scan_result_links_to_downloadable_html_report(ui, http_server):
    data = scan(ui, {"target": http_server(MockHandler), "authorized": True}).json()
    assert data["report_url"] == f"/api/report/{data['report_id']}.html"

    resp = requests.get(ui + data["report_url"], timeout=5)
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/html")
    disposition = resp.headers["Content-Disposition"]
    assert disposition.startswith('attachment; filename="websec-scan-127.0.0.1_') and disposition.endswith('.html"')
    assert "Non-intrusive Web Security Scan Report" in resp.text
    assert "EXPOSURE-ENV" in resp.text


def test_report_ids_are_unguessable_and_unknown_ids_404(ui, http_server):
    target = http_server(MockHandler)
    first = scan(ui, {"target": target, "authorized": True}).json()["report_id"]
    second = scan(ui, {"target": target, "authorized": True}).json()["report_id"]
    assert first != second and len(first) >= 16
    assert requests.get(f"{ui}/api/report/{'A' * 22}.html", timeout=5).status_code == 404
    assert requests.get(f"{ui}/api/report/../index.html", timeout=5).status_code == 404


def test_only_recent_reports_are_kept(ui, monkeypatch):
    monkeypatch.setattr(
        web,
        "run_scan",
        lambda target, timeout, workers, **kwargs: ScanResult(target=target, started_at="2026-01-01T00:00:00Z"),
    )
    ids = [
        scan(ui, {"target": "http://127.0.0.1:1", "authorized": True}).json()["report_id"]
        for _ in range(web._MAX_STORED_REPORTS + 1)
    ]
    assert requests.get(f"{ui}/api/report/{ids[0]}.html", timeout=5).status_code == 404
    assert requests.get(f"{ui}/api/report/{ids[-1]}.html", timeout=5).status_code == 200


def test_report_download_blocks_rebinding_host(ui, http_server):
    report_url = scan(ui, {"target": http_server(MockHandler), "authorized": True}).json()["report_url"]
    port = ui.rsplit(":", 1)[1]
    resp = requests.get(ui + report_url, headers={"Host": f"evil.example:{port}"}, timeout=5)
    assert resp.status_code == 403


def test_ui_text_is_english():
    # English is the default language of the system; guard against untranslated strings.
    import re
    from pathlib import Path

    static = Path(web.__file__).with_name("static")
    html = (static / "index.html").read_text(encoding="utf-8")
    assert '<html lang="en">' in html
    for name in ("index.html", "app.js", "app.css"):
        text = (static / name).read_text(encoding="utf-8")
        assert not re.search(r"[À-ɏḀ-ỿ]", text), f"non-English text in {name}"
    assert "Download Test result" in html


def test_internal_scan_error_returns_500_and_frees_the_scan_slot(ui, monkeypatch, capsys):
    def broken_scan(*args, **kwargs):
        raise RuntimeError("boom while fetching https://scan-user:hunter2@t.example/")

    monkeypatch.setattr(web, "run_scan", broken_scan)
    resp = scan(ui, {"target": "https://t.example/", "authorized": True})
    assert resp.status_code == 500
    assert resp.json() == {"error": "The scan failed with an internal error; see the server console for details."}
    logged = capsys.readouterr().err
    assert "RuntimeError" in logged and "hunter2" not in logged and "scan-user" not in logged
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: ScanResult(target="https://t.example/", started_at="x"))
    assert scan(ui, {"target": "https://t.example/", "authorized": True}).status_code == 200  # lock released


def test_scan_of_unreachable_target_reports_error(ui, closed_port):
    resp = scan(ui, {"target": f"http://127.0.0.1:{closed_port}", "authorized": True})
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings"] == [] and len(data["errors"]) == 1
    assert data["gate_failed"] is False


@pytest.mark.parametrize("authorized", [None, False, "true", 1])
def test_scan_requires_explicit_authorization(ui, monkeypatch, authorized):
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: pytest.fail("scan ran without authorization"))
    payload = {"target": "https://example.invalid"}
    if authorized is not None:
        payload["authorized"] = authorized
    resp = scan(ui, payload)
    assert resp.status_code == 400
    assert "Authorization not confirmed" in resp.json()["error"]


# The same targets AT-75 names for the CLI: both entry points must refuse all of them.
@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        None,
        42,
        "ftp://example.com",
        "gopher://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,x",
        "http://",
        "https:///path",
    ],
)
def test_scan_rejects_invalid_targets(ui, monkeypatch, target):
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: pytest.fail("scan ran for an invalid target"))
    assert scan(ui, {"target": target, "authorized": True}).status_code == 400


def test_post_to_unknown_path_is_404_even_with_body(ui):
    # The body must be read before replying, or Windows resets the connection.
    resp = requests.post(f"{ui}/api/other", json={"target": "x", "authorized": True}, timeout=5)
    assert resp.status_code == 404


def test_scan_rejects_non_json_body(ui):
    resp = requests.post(
        f"{ui}/api/scan",
        data="target=x&authorized=true",
        timeout=5,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 415


def test_scan_rejects_cross_origin(ui, monkeypatch):
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: pytest.fail("cross-origin scan ran"))
    resp = scan(
        ui, {"target": "https://example.invalid", "authorized": True}, headers={"Origin": "https://evil.example"}
    )
    assert resp.status_code == 403


def test_rejects_dns_rebinding_host(ui, monkeypatch):
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: pytest.fail("rebinding scan ran"))
    port = ui.rsplit(":", 1)[1]
    rebinding = {"Host": f"evil.example:{port}", "Origin": f"http://evil.example:{port}"}
    assert requests.get(ui + "/", headers=rebinding, timeout=5).status_code == 403
    assert scan(ui, {"target": "https://example.invalid", "authorized": True}, headers=rebinding).status_code == 403


def test_same_origin_request_is_allowed(ui, http_server):
    resp = scan(ui, {"target": http_server(MockHandler), "authorized": True}, headers={"Origin": ui})
    assert resp.status_code == 200


def test_oversized_body_rejected(ui):
    assert scan(ui, {"target": "x" * 5000, "authorized": True}).status_code == 413


def test_only_one_scan_at_a_time(ui, monkeypatch):
    started, release = threading.Event(), threading.Event()

    def slow_scan(target, timeout, workers, **kwargs):
        started.set()
        release.wait(10)
        return ScanResult(target=target, started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z")

    monkeypatch.setattr(web, "run_scan", slow_scan)
    first = threading.Thread(target=scan, args=(ui, {"target": "http://127.0.0.1:1", "authorized": True}))
    first.start()
    assert started.wait(10)
    try:
        assert scan(ui, {"target": "http://127.0.0.1:1", "authorized": True}).status_code == 429
    finally:
        release.set()
        first.join(10)


def test_bind_address_decides_host_check():
    loopback = web.build_server("127.0.0.1", 0)
    try:
        assert loopback.loopback_only is True
    finally:
        loopback.server_close()
    assert web._is_loopback("localhost") and web._is_loopback("::1") and not web._is_loopback("0.0.0.0")  # noqa: S104 - test data, nothing binds here


# --- access token (FR-WEB-02) ---------------------------------------------------------
#
# These tests build the server bound to 127.0.0.1 (a real, safe loopback bind) but with
# access_token set explicitly, which exercises exactly the same request-handling code as a
# real --allow-remote server. Binding 0.0.0.0/a real interface is deliberately not exercised
# here: on the Windows dev machine that would risk a Firewall permission prompt with nobody
# to click it, and CI runners cannot meaningfully test "is this socket reachable from outside"
# either. Only the refusal-without-flag path (main(), no bind attempted) is tested end to end.


@pytest.fixture
def token_ui():
    server = web.build_server("127.0.0.1", 0, timeout=5, access_token="right-token")  # noqa: S106 - test fixture
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_default_bind_never_requires_a_token(ui):
    assert requests.get(ui + "/", timeout=5).status_code == 200


def test_missing_or_wrong_token_is_rejected_on_every_route(token_ui, http_server):
    assert requests.get(token_ui + "/", timeout=5).status_code == 403
    assert requests.get(token_ui + "/", headers={"X-Scanner-Token": "wrong"}, timeout=5).status_code == 403
    assert requests.get(token_ui + "/api/checks", timeout=5).status_code == 403
    assert requests.get(token_ui + "/app.js", timeout=5).status_code == 403  # static files too
    resp = scan(token_ui, {"target": http_server(MockHandler), "authorized": True})
    assert resp.status_code == 403


def test_correct_token_is_accepted_via_header_or_query(token_ui, http_server):
    assert requests.get(token_ui + "/", headers={"X-Scanner-Token": "right-token"}, timeout=5).status_code == 200
    assert requests.get(token_ui + "/?token=right-token", timeout=5).status_code == 200
    resp = scan(
        token_ui,
        {"target": http_server(MockHandler), "authorized": True},
        headers={"X-Scanner-Token": "right-token"},
    )
    assert resp.status_code == 200


def test_valid_query_token_sets_a_cookie_used_by_later_same_origin_requests(token_ui):
    session = requests.Session()
    first = session.get(token_ui + "/?token=right-token", timeout=5)
    assert first.status_code == 200
    set_cookie = first.headers["Set-Cookie"]
    assert "websec_scanner_token=right-token" in set_cookie
    assert "HttpOnly" in set_cookie and "SameSite=Strict" in set_cookie
    # No header, no query string this time: the cookie alone must be enough.
    assert session.get(token_ui + "/app.js", timeout=5).status_code == 200
    assert session.get(token_ui + "/api/checks", timeout=5).status_code == 200


def test_wrong_query_token_does_not_set_a_cookie(token_ui):
    resp = requests.get(token_ui + "/?token=wrong", timeout=5)
    assert resp.status_code == 403 and "Set-Cookie" not in resp.headers


def test_access_token_never_appears_in_server_logs(token_ui, capsys):
    requests.get(token_ui + "/?token=right-token", timeout=5)
    logged = capsys.readouterr().err
    assert "right-token" not in logged
    assert "token=<redacted" in logged


def test_remote_bind_without_allow_remote_refuses_to_start(capsys, monkeypatch):
    monkeypatch.setattr(web, "build_server", lambda *a, **kw: pytest.fail("must not bind before refusing to start"))
    with pytest.raises(SystemExit) as exc:
        web.main(["--host", "0.0.0.0"])  # noqa: S104 - the argument under test; never actually bound
    assert exc.value.code == 2
    assert "--allow-remote" in capsys.readouterr().err


def test_web_ui_headers_pass_the_scanners_own_check(ui):
    from websec_scanner.checks import headers as headers_check

    resp = requests.get(ui + "/", timeout=5)
    found = headers_check.check_security_headers(ui + "/", dict(resp.headers), is_https=False)
    assert not [f for f in found if f.severity.value in ("CRITICAL", "HIGH", "MEDIUM")]


# --- check groups (SRS 4.11) ---------------------------------------------------------


def test_checks_endpoint_lists_the_groups(ui):
    resp = requests.get(f"{ui}/api/checks", timeout=5)
    assert resp.status_code == 200 and resp.headers["Content-Type"].startswith("application/json")
    assert resp.json() == {
        "groups": [{"id": g.id, "title": g.title, "description": g.description} for g in catalog.CHECK_GROUPS],
        # FR-UI-14: the limits a crawl runs under, so the page can state them (the CLI defaults here)
        "crawl": {"max_depth": 2, "max_pages": 50, "max_duration": 60.0},
    }


def test_checks_endpoint_blocks_rebinding_host(ui):
    port = ui.rsplit(":", 1)[1]
    assert requests.get(f"{ui}/api/checks", headers={"Host": f"evil.example:{port}"}, timeout=5).status_code == 403


def test_scan_runs_only_the_selected_groups_and_returns_grouped_views(ui, http_server):
    data = scan(ui, {"target": http_server(MockHandler), "authorized": True, "checks": ["cookies", "headers"]}).json()
    assert data["scan_groups"] == ["headers", "cookies"]
    report = {k: v for k, v in data.items() if k not in web.WEB_ONLY_FIELDS}
    assert data["groups"] == output.group_findings(report)
    assert data["owasp_groups"] == output.owasp_groups(report)
    assert {g["id"]: g["status"] for g in data["groups"]}["tls"] == "not-selected"


def test_scan_without_checks_runs_every_group(ui, http_server):
    data = scan(ui, {"target": http_server(MockHandler), "authorized": True}).json()
    assert data["scan_groups"] == list(catalog.GROUP_IDS)


@pytest.mark.parametrize("checks", [[], ["bogus"], "headers", [1], None])
def test_scan_rejects_an_invalid_check_selection(ui, monkeypatch, checks):
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: pytest.fail("scan ran with an invalid selection"))
    resp = scan(ui, {"target": "https://t.example/", "authorized": True, "checks": checks})
    assert resp.status_code == 400 and "check group" in resp.json()["error"].lower()
