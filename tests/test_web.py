"""Tests for the local web UI server (owasp_scanner.web)."""

from __future__ import annotations

import threading

import pytest
import requests
from mock_server import Handler as MockHandler

from owasp_scanner import web
from owasp_scanner.models import ScanResult


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
    assert disposition.startswith('attachment; filename="owasp-scan-127.0.0.1_') and disposition.endswith('.html"')
    assert "OWASP Passive Scan Report" in resp.text
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
        lambda target, timeout, workers: ScanResult(target=target, started_at="2026-01-01T00:00:00Z"),
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


@pytest.mark.parametrize("target", ["", "   ", None, 42, "ftp://example.com", "file:///etc/passwd"])
def test_scan_rejects_invalid_targets(ui, monkeypatch, target):
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: pytest.fail("scan ran for an invalid target"))
    assert scan(ui, {"target": target, "authorized": True}).status_code == 400


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

    def slow_scan(target, timeout, workers):
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
    assert web._is_loopback("localhost") and web._is_loopback("::1") and not web._is_loopback("0.0.0.0")
