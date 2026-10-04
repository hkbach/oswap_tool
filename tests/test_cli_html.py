"""FR-RPT-09: --html in the CLI uses the same renderer as the Web UI download."""

from __future__ import annotations

import json
import threading

import requests
from mock_server import Handler as MockHandler
from test_redact import COOKIE_SECRET, SecretHandler

from websec_scanner import cli, output, web
from websec_scanner.html_report import render_html


def test_cli_html_is_render_html_of_the_json_report(http_server, tmp_path):
    json_out, html_out = tmp_path / "r.json", tmp_path / "r.html"
    cli.main([http_server(MockHandler), "--yes", "--no-color", "--json", str(json_out), "--html", str(html_out)])
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert html_out.read_text(encoding="utf-8") == render_html(report)


def test_web_download_uses_the_same_renderer(http_server):
    server = web.build_server("127.0.0.1", 0, timeout=5)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    ui = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        data = requests.post(
            f"{ui}/api/scan", json={"target": http_server(MockHandler), "authorized": True}, timeout=60
        )
        report = {k: v for k, v in data.json().items() if k not in web.WEB_ONLY_FIELDS}
        downloaded = requests.get(ui + data.json()["report_url"], timeout=5).text
    finally:
        server.shutdown()
        server.server_close()
    assert downloaded == render_html(report)


def test_cli_html_is_redacted_and_escaped(http_server, tmp_path):
    html_out = tmp_path / "r.html"
    cli.main([http_server(SecretHandler), "--yes", "--no-color", "--html", str(html_out)])
    html = html_out.read_text(encoding="utf-8")
    assert COOKIE_SECRET not in html and "<script" not in html


def test_cli_html_with_show_secrets_carries_the_warning(http_server, tmp_path):
    html_out = tmp_path / "r.html"
    cli.main([http_server(SecretHandler), "--yes", "--no-color", "--show-secrets", "--html", str(html_out)])
    assert "Secrets are not redacted" in html_out.read_text(encoding="utf-8")


def test_all_outputs_in_one_run_agree(http_server, tmp_path):
    outs = {k: tmp_path / f"r.{k}" for k in ("json", "html", "sarif")}
    cli.main(
        [http_server(MockHandler), "--yes", "--no-color", *[a for k, p in outs.items() for a in (f"--{k}", str(p))]]
    )
    report = json.loads(outs["json"].read_text(encoding="utf-8"))
    sarif_doc = json.loads(outs["sarif"].read_text(encoding="utf-8"))
    html = outs["html"].read_text(encoding="utf-8")
    assert len(sarif_doc["runs"][0]["results"]) == len(report["findings"])
    assert html.count('id="finding-') == len(report["findings"])  # the HTML shows the same set
    assert output.gate_failed(report) is report["gate"]["failed"]
