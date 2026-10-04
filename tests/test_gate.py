"""FR-CI-01: --fail-on threshold, exit code 3 for an incomplete scan, one gate for CLI/Web/HTML."""

from __future__ import annotations

import json
import threading

import pytest
import requests
from conftest import QuietHandler
from mock_server import Handler as MockHandler

from websec_scanner import cli, output, web
from websec_scanner.html_report import render_html

EMPTY = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}


@pytest.mark.parametrize(
    "counts, fail_on, failed",
    [
        ({"CRITICAL": 1}, "critical", True),
        ({"HIGH": 1}, "critical", False),
        ({"HIGH": 1}, "high", True),
        ({"MEDIUM": 1}, "high", False),
        ({"MEDIUM": 1}, "medium", True),
        ({"LOW": 1}, "medium", False),
        ({"LOW": 1}, "low", True),
        ({"INFO": 5}, "low", False),
        ({"CRITICAL": 3}, "none", False),
    ],
)
def test_threshold(counts, fail_on, failed):
    assert output.gate_failed({"summary": {**EMPTY, **counts}}, fail_on) is failed


def test_default_threshold_is_high():
    assert output.gate_failed({"summary": {**EMPTY, "HIGH": 1}}) is True
    assert output.gate_failed({"summary": {**EMPTY, "MEDIUM": 1}}) is False


class MediumOnly(QuietHandler):
    """Plain HTTP target; with the redirect verdict neutralised it yields MEDIUM/LOW/INFO only."""

    def do_GET(self):
        self.send(200 if self.path == "/" else 404, b"<html><body>ok</body></html>", {"Content-Type": "text/html"})


@pytest.fixture
def medium_only(http_server, monkeypatch):
    monkeypatch.setattr(cli.redirect_check, "evaluate_redirect_chain", lambda start, chain: [])
    return http_server(MediumOnly)


@pytest.mark.parametrize("fail_on, code", [("low", 1), ("medium", 1), ("high", 0), ("critical", 0), ("none", 0)])
def test_exit_code_follows_the_threshold(medium_only, fail_on, code):
    assert cli.main([medium_only, "--yes", "--no-color", "--fail-on", fail_on]) == code


def test_critical_target_with_fail_on_none_passes(http_server):
    assert cli.main([http_server(MockHandler), "--yes", "--no-color", "--fail-on", "none"]) == 0


def test_unreachable_target_exits_3(closed_port):
    assert cli.main([f"http://127.0.0.1:{closed_port}/", "--yes", "--no-color", "--timeout", "2"]) == 3


def test_unreachable_target_with_fail_on_none_exits_0(closed_port):
    target = f"http://127.0.0.1:{closed_port}/"
    assert cli.main([target, "--yes", "--no-color", "--timeout", "2", "--fail-on", "none"]) == 0


def test_findings_over_the_threshold_win_over_incomplete(https_server):
    # Expired certificate: the baseline fails (incomplete) but TLS-CERT-EXPIRED is CRITICAL.
    base, _ = https_server(MediumOnly, cert="expired")
    assert cli.main([base, "--yes", "--no-color", "--timeout", "5"]) == 1


def test_json_records_the_gate(medium_only, tmp_path, closed_port):
    out = tmp_path / "r.json"
    cli.main([medium_only, "--yes", "--no-color", "--fail-on", "medium", "--json", str(out)])
    gate = json.loads(out.read_text(encoding="utf-8"))["gate"]
    assert gate == {
        "fail_on": "medium",
        "failed": True,
        "incomplete": False,
        "incomplete_reason": None,
        "basis": "all",  # no --baseline: every finding counts
        "counted": gate["counted"],  # the per-severity numbers are checked below
    }
    assert gate["counted"]["MEDIUM"] > 0
    cli.main([f"http://127.0.0.1:{closed_port}/", "--yes", "--no-color", "--timeout", "2", "--json", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["gate"] == {
        "fail_on": "high",
        "failed": False,
        "incomplete": True,
        "incomplete_reason": "home-page",
        "basis": "all",
        "counted": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    }


def test_web_ui_uses_the_server_threshold(medium_only):
    server = web.build_server("127.0.0.1", 0, timeout=5, fail_on="medium")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/api/scan"
        data = requests.post(url, json={"target": medium_only, "authorized": True}, timeout=60).json()
    finally:
        server.shutdown()
        server.server_close()
    assert data["gate_failed"] is True and data["gate"]["fail_on"] == "medium"


def test_html_report_names_the_threshold(medium_only):
    report = output.build_report(cli.run_scan(medium_only, timeout=5), fail_on="medium")
    html = render_html(report)
    assert "--fail-on medium threshold: the CLI exits with code 1" in html


def test_cli_rejects_an_unknown_threshold(capsys):
    with pytest.raises(SystemExit):
        cli.main(["https://example.invalid", "--yes", "--fail-on", "severe"])
    assert "--fail-on" in capsys.readouterr().err


@pytest.mark.parametrize("fail_on", ["high", "none"])
def test_web_ui_and_html_report_show_the_same_gate_message(closed_port, fail_on):
    # An unreachable target is incomplete; with "none" the two views used to disagree.
    server = web.build_server("127.0.0.1", 0, timeout=2, fail_on=fail_on)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    ui = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        target = f"http://127.0.0.1:{closed_port}/"
        data = requests.post(f"{ui}/api/scan", json={"target": target, "authorized": True}, timeout=60).json()
        html = requests.get(ui + data["report_url"], timeout=5).text
    finally:
        server.shutdown()
        server.server_close()
    status, message = output.gate_message(data["gate"])
    assert (data["gate_status"], data["gate_message"]) == (status, message) and status == "warn"
    assert message in html
    assert ("code 0 (--fail-on none)" in message) is (fail_on == "none")
