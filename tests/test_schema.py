"""FR-MODEL-02: versioned JSON report, validated against docs/report.schema.json."""

from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path

import jsonschema
import pytest
import requests
from mock_server import Handler as MockHandler

from websec_scanner import __version__, cli, output, rule_loader, web
from websec_scanner.models import SCHEMA_VERSION

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "report.schema.json"
WEB_ONLY_FIELDS = set(web.WEB_ONLY_FIELDS)


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_schema_version_matches_the_schema_file(validator):
    assert validator.schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION == "1.10"


def test_cli_json_report_matches_schema(validator, http_server, tmp_path):
    out = tmp_path / "report.json"
    cli.main([http_server(MockHandler), "--yes", "--no-color", "--json", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    validator.validate(data)
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["scanner_version"] == __version__
    assert data["rules_version"] == rule_loader.rules_version()
    assert uuid.UUID(data["scan_id"]).version == 4


def test_failed_scan_report_matches_schema(validator, closed_port):
    validator.validate(output.build_report(cli.run_scan(f"http://127.0.0.1:{closed_port}/", timeout=2)))


def test_every_scan_gets_a_new_scan_id(http_server):
    base = http_server(MockHandler)
    assert cli.run_scan(base).scan_id != cli.run_scan(base).scan_id


def test_web_response_is_the_report_plus_web_fields(validator, http_server):
    server = web.build_server("127.0.0.1", 0, timeout=5)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/api/scan"
        data = requests.post(url, json={"target": http_server(MockHandler), "authorized": True}, timeout=60).json()
    finally:
        server.shutdown()
        server.server_close()
    assert WEB_ONLY_FIELDS <= set(data)
    validator.validate({k: v for k, v in data.items() if k not in WEB_ONLY_FIELDS})


def test_schema_rejects_unknown_fields(validator):
    report = output.build_report(cli.ScanResult(target="https://t/", started_at="2026-01-01T00:00:00Z"))
    validator.validate(report)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**report, "surprise": 1})
