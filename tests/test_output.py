"""FR-WEB-01: CLI and Web UI share one output pipeline (build_report / gate_failed)."""

from __future__ import annotations

import json
import re
import threading

import pytest
import requests
from mock_server import Handler as MockHandler
from test_acceptance import SoftNotFoundHandler

from owasp_scanner import cli, output, web

VOLATILE = {"scan_id", "started_at", "finished_at"}
WEB_ONLY = set(web.WEB_ONLY_FIELDS)


@pytest.fixture
def ui():
    server = web.build_server("127.0.0.1", 0, timeout=5)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _stable(report: dict) -> dict:
    return {k: v for k, v in report.items() if k not in VOLATILE | WEB_ONLY}


def _cli_json(target: str, tmp_path) -> tuple[dict, int]:
    out = tmp_path / "cli.json"
    code = cli.main([target, "--yes", "--no-color", "--json", str(out)])
    return json.loads(out.read_text(encoding="utf-8")), code


@pytest.mark.parametrize("handler, gate", [(MockHandler, True), (SoftNotFoundHandler, False)])
def test_cli_and_web_ui_produce_the_same_report(ui, http_server, tmp_path, monkeypatch, handler, gate):
    if not gate:
        # A plain-HTTP target always fails the gate since FIX-09; pretend the redirect is
        # fine so both a failing and a passing gate are compared.
        monkeypatch.setattr(cli.redirect_check, "evaluate_redirect_chain", lambda start, chain: [])
    target = http_server(handler)
    cli_report, exit_code = _cli_json(target, tmp_path)
    web_report = requests.post(f"{ui}/api/scan", json={"target": target, "authorized": True}, timeout=60).json()

    assert _stable(cli_report) == _stable(web_report)
    assert web_report["gate_failed"] is gate
    assert (exit_code == 1) is gate  # one gate rule for both entry points


def test_download_json_in_the_ui_strips_exactly_the_web_only_fields():
    # app.js removes these before saving, so the file equals the CLI --json output.
    app_js = (web._STATIC_DIR / "app.js").read_text(encoding="utf-8")
    stripped = re.search(r"const \{ ([\w, ]+), \.\.\.report \} = lastResult;", app_js).group(1)
    assert set(stripped.split(", ")) == set(web.WEB_ONLY_FIELDS)


def test_gate_rule():
    empty = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    assert output.gate_failed({"summary": empty}) is False
    assert output.gate_failed({"summary": {**empty, "MEDIUM": 3, "INFO": 1}}) is False
    assert output.gate_failed({"summary": {**empty, "HIGH": 1}}) is True
    assert output.gate_failed({"summary": {**empty, "CRITICAL": 1}}) is True


def test_build_report_sorts_findings(http_server):
    report = output.build_report(cli.run_scan(http_server(MockHandler)))
    ranks = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    order = [ranks.index(f["severity"]) for f in report["findings"]]
    assert order == sorted(order)


# --- contract: status codes and content types of the two endpoints ----------------


@pytest.mark.parametrize(
    "kwargs, status",
    [
        ({"json": {"target": "https://example.invalid"}}, 400),
        ({"json": {"target": "", "authorized": True}}, 400),
        ({"data": b"{not json", "headers": {"Content-Type": "application/json"}}, 400),
        ({"json": ["not", "an", "object"]}, 400),
        ({"json": {"target": "x", "authorized": True}, "headers": {"Origin": "https://evil.example"}}, 403),
        ({"data": b"target=x", "headers": {"Content-Type": "text/plain"}}, 415),
        ({"data": b"x" * 5000, "headers": {"Content-Type": "application/json"}}, 413),
    ],
)
def test_scan_errors_are_json_with_an_error_message(ui, monkeypatch, kwargs, status):
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: pytest.fail("scan must not run"))
    resp = requests.post(f"{ui}/api/scan", timeout=5, **kwargs)
    assert resp.status_code == status
    assert resp.headers["Content-Type"] == "application/json; charset=utf-8"
    assert isinstance(resp.json()["error"], str) and resp.json()["error"]


def test_report_endpoint_contract(ui, http_server):
    data = requests.post(f"{ui}/api/scan", json={"target": http_server(MockHandler), "authorized": True}, timeout=60)
    assert data.headers["Content-Type"] == "application/json; charset=utf-8"
    report = requests.get(ui + data.json()["report_url"], timeout=5)
    assert report.headers["Content-Type"] == "text/html; charset=utf-8"
    assert report.headers["Content-Disposition"].startswith("attachment;")
    missing = requests.get(f"{ui}/api/report/{'x' * 22}.html", timeout=5)
    assert missing.status_code == 404
    assert missing.headers["Content-Type"] == "application/json; charset=utf-8"


def test_finding_order_is_deterministic():
    # Sensitive-path findings arrive in completion order of parallel requests; the
    # report order must not depend on it (severity, then id, then instance_key).
    from owasp_scanner.models import Finding, ScanResult, Severity

    def finding(fid, sev, key):
        return Finding(id=fid, title="t", severity=sev, owasp_category="c", description="d", instance_key=key)

    items = [
        finding("EXPOSURE-GIT-HEAD", Severity.CRITICAL, ".git/HEAD"),
        finding("HDR-X", Severity.LOW, "x"),
        finding("EXPOSURE-ENV", Severity.CRITICAL, ".env"),
        finding("COOKIE-FLAGS-MISSING", Severity.MEDIUM, "b"),
        finding("COOKIE-FLAGS-MISSING", Severity.MEDIUM, "a"),
    ]
    orders = set()
    for items_in in (items, items[::-1]):
        result = ScanResult(target="https://t/", started_at="2026-01-01T00:00:00Z", findings=list(items_in))
        orders.add(tuple((f["id"], f["instance_key"]) for f in output.build_report(result)["findings"]))
    assert orders == {
        (
            ("EXPOSURE-ENV", ".env"),
            ("EXPOSURE-GIT-HEAD", ".git/HEAD"),
            ("COOKIE-FLAGS-MISSING", "a"),
            ("COOKIE-FLAGS-MISSING", "b"),
            ("HDR-X", "x"),
        )
    }
