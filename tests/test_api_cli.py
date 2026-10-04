"""FR-API-01 (decision D9): ``--api-spec`` puts an API inventory in the console and JSON reports.

The inventory is read from a file the operator names. It is shown, not scanned: no request goes to
any endpoint or server the spec names. A bad spec stops the run before the first request, with the
same exit code as any other bad argument.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

import jsonschema
import pytest
import requests
from conftest import QuietHandler
from mock_server import Handler as MockHandler

from websec_scanner import cli, output, web
from websec_scanner.api import inventory
from websec_scanner.models import SCHEMA_VERSION, ScanResult
from websec_scanner.redact import redact

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "report.schema.json"

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Pet Store", "version": "2.1"},
    "servers": [{"url": "https://api.example.com/v1"}],
    "security": [{"key": []}],
    "paths": {
        "/pets": {
            "get": {"operationId": "listPets", "parameters": [{"name": "limit", "in": "query"}]},
            "post": {"operationId": "createPet", "security": []},
        },
        "/pets/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": True}]}},
    },
    "components": {"securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
}


def _alias_bomb() -> str:
    """Nine levels of nine aliases each: a few hundred bytes that stand for 9**9 values."""
    lines = ["openapi: 3.0.3", "x-0: &a0 [1, 2, 3, 4, 5, 6, 7, 8, 9]"]
    for level in range(1, 9):
        refs = ", ".join([f"*a{level - 1}"] * 9)
        lines.append(f"x-{level}: &a{level} [{refs}]")
    return "\n".join([*lines, "paths: {}", ""])


ALIAS_BOMB = _alias_bomb()


@pytest.fixture
def spec_file(tmp_path):
    path = tmp_path / "api.json"
    path.write_text(json.dumps(SPEC), encoding="utf-8")
    return path


def scan(target, *args, capsys):
    code = cli.main([target, "--yes", "--no-color", "--checks", "headers", *args])
    return code, capsys.readouterr()


def report_of(target, tmp_path, *args):
    out = tmp_path / "report.json"
    cli.main([target, "--yes", "--no-color", "--checks", "headers", "--json", str(out), *args])
    return json.loads(out.read_text(encoding="utf-8"))


# --- the JSON report ---


def test_the_json_report_carries_the_inventory(http_server, tmp_path, spec_file):
    data = report_of(http_server(MockHandler), tmp_path, "--api-spec", str(spec_file))
    api = data["api"]
    assert (api["source"], api["format"], api["version"], api["title"]) == ("api.json", "openapi", "3.0.3", "Pet Store")
    assert api["servers"] == ["https://api.example.com/v1"]
    assert api["endpoint_count"] == 3 == len(api["endpoints"])
    assert [(e["method"], e["path"]) for e in api["endpoints"]] == [
        ("GET", "/pets"),
        ("POST", "/pets"),
        ("GET", "/pets/{id}"),
    ]
    assert api["endpoints"][1]["security"] == []
    assert api["endpoints"][0]["security"] == ["key"]
    assert api["security_schemes"] == [{"name": "key", "type": "apiKey", "detail": "header X-API-Key"}]


def test_without_a_spec_the_field_is_null_so_the_shape_never_changes(http_server, tmp_path):
    assert report_of(http_server(MockHandler), tmp_path)["api"] is None


def test_the_schema_version_matches_the_schema_file_and_the_report_validates(http_server, tmp_path, spec_file):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION
    for extra in ((), ("--api-spec", str(spec_file))):
        data = report_of(http_server(MockHandler), tmp_path, *extra)
        validator.validate(data)
        assert data["schema_version"] == SCHEMA_VERSION


def test_the_schema_is_strict_about_the_inventory(http_server, tmp_path, spec_file):
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
    data = report_of(http_server(MockHandler), tmp_path, "--api-spec", str(spec_file))
    for mutate in (
        lambda d: d["api"].update(surprise=1),
        lambda d: d["api"]["endpoints"][0].update(surprise=1),
        lambda d: d["api"]["endpoints"][0]["parameters"][0].update(surprise=1),
        lambda d: d["api"].update(endpoint_count="3"),
        lambda d: d["api"]["endpoints"][0].update(method="get"),
        lambda d: d["api"].pop("servers"),
        lambda d: d.pop("api"),
    ):
        broken = json.loads(json.dumps(data))
        mutate(broken)
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(broken)


def test_the_exit_code_does_not_depend_on_the_spec(http_server, spec_file):
    target = http_server(MockHandler)
    argv = [target, "--yes", "--no-color", "--checks", "headers,exposed-files"]
    assert cli.main(argv) == cli.main([*argv, "--api-spec", str(spec_file)])


# --- the console ---


def test_the_console_lists_the_inventory(http_server, spec_file, capsys):
    _, captured = scan(http_server(MockHandler), "--api-spec", str(spec_file), capsys=capsys)
    out = captured.out
    assert "API inventory" in out and "Pet Store" in out and "openapi 3.0.3" in out and "api.json" in out
    assert "https://api.example.com/v1" in out
    assert "GET" in out and "/pets/{id}" in out and "limit (query)" in out
    assert "key (apiKey, header X-API-Key)" in out


def test_without_a_spec_the_console_has_no_inventory(http_server, capsys):
    _, captured = scan(http_server(MockHandler), capsys=capsys)
    assert "API inventory" not in captured.out


def test_a_long_inventory_is_cut_on_the_console_but_complete_in_the_json(http_server, tmp_path, capsys):
    many = dict(SPEC, paths={f"/r{i:03d}": {"get": {}} for i in range(150)})
    path = tmp_path / "many.json"
    path.write_text(json.dumps(many), encoding="utf-8")
    target = http_server(MockHandler)
    _, captured = scan(target, "--api-spec", str(path), capsys=capsys)
    assert "/r000" in captured.out and "/r099" in captured.out and "/r100" not in captured.out
    assert "and 50 more" in captured.out
    assert report_of(target, tmp_path, "--api-spec", str(path))["api"]["endpoint_count"] == 150


def test_text_from_the_spec_cannot_drive_the_terminal(http_server, tmp_path, capsys):
    hostile = dict(SPEC, info={"title": "\x1b[2K\x1b[1Atrusted\x9b", "version": "1"}, paths={"/a\x1b[2K": {"get": {}}})
    path = tmp_path / "hostile.json"
    path.write_text(json.dumps(hostile), encoding="utf-8")
    _, captured = scan(http_server(MockHandler), "--api-spec", str(path), capsys=capsys)
    assert "\x1b" not in captured.out and "\x9b" not in captured.out
    assert "\\x1b[2K" in captured.out, "made visible, not dropped"


# --- nothing in the spec is ever requested ---


class Recording(QuietHandler):
    seen: list[str] = []

    def do_GET(self):
        Recording.seen.append(self.path)
        self.send(404)


def test_no_request_goes_to_an_endpoint_the_spec_names(http_server, tmp_path, spec_file):
    Recording.seen = []
    cli.main([http_server(Recording), "--yes", "--no-color", "--api-spec", str(spec_file)])
    assert Recording.seen, "the scan itself still ran"
    assert not [p for p in Recording.seen if p.startswith("/pets")]


def test_no_connection_is_made_to_a_server_the_spec_names(http_server, tmp_path):
    bystander = http_server(Recording)  # the spec names it as its server; the scan must never touch it
    Recording.seen = []
    spec = dict(SPEC, servers=[{"url": bystander}])
    path = tmp_path / "bystander.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    target = http_server(MockHandler)
    cli.main([target, "--yes", "--no-color", "--checks", "headers", "--api-spec", str(path)])
    assert Recording.seen == []


def test_credentials_in_a_server_url_are_masked_everywhere(http_server, tmp_path, capsys):
    spec = dict(SPEC, servers=[{"url": "https://svc-user:s3cr3t-pw@api.example.com/v1?api_key=abcd1234"}])
    path = tmp_path / "creds.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    target = http_server(MockHandler)
    out = tmp_path / "r.json"
    cli.main([target, "--yes", "--no-color", "--checks", "headers", "--json", str(out), "--api-spec", str(path)])
    shown = capsys.readouterr().out + out.read_text(encoding="utf-8")
    assert "s3cr3t-pw" not in shown and "abcd1234" not in shown and "svc-user" not in shown
    assert "api.example.com" in shown


# --- a bad spec stops the run before any request ---


@pytest.mark.parametrize(
    "name, content, message",
    [
        ("missing.json", None, "does not exist|cannot read"),
        ("spec.txt", "{}", "extension"),
        ("bad.json", "{not json", "JSON"),
        ("other.json", '{"info": {}}', "not an OpenAPI"),
        (
            "ssrf.json",
            json.dumps({"openapi": "3.0.3", "paths": {"/a": {"$ref": "http://169.254.169.254/latest"}}}),
            "not allowed",
        ),
        (
            "bomb.yaml",
            ALIAS_BOMB,
            "alias|expand",
        ),
    ],
)
def test_a_bad_spec_is_refused_with_exit_code_2_before_any_request(
    monkeypatch, tmp_path, capsys, name, content, message
):
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: pytest.fail("a scan started with a bad spec"))
    path = tmp_path / name
    if content is not None:
        path.write_text(content, encoding="utf-8")
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["https://t.example/", "--yes", "--api-spec", str(path)])
    assert exit_info.value.code == 2
    err = capsys.readouterr().err
    assert "--api-spec" in err and name in err
    assert re.search(message, err), err


# --- several targets, config files ---


def test_every_target_report_carries_the_same_inventory(http_server, tmp_path, spec_file):
    a, b = http_server(MockHandler), http_server(MockHandler)
    out = tmp_path / "out"
    cli.main(
        [
            a,
            b,
            "--yes",
            "--no-color",
            "--checks",
            "headers",
            "--output-dir",
            str(out),
            "--formats",
            "json",
            "--api-spec",
            str(spec_file),
        ]
    )
    reports = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(out.glob("*.json"))]
    assert len(reports) == 2 and reports[0]["api"] == reports[1]["api"] and reports[0]["api"]["endpoint_count"] == 3


def test_the_config_file_can_name_the_spec_relative_to_itself(http_server, tmp_path, spec_file):
    config = tmp_path / "scanner.toml"
    config.write_text('api_spec = "api.json"\nchecks = ["headers"]\n', encoding="utf-8")
    out = tmp_path / "r.json"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    cwd = os.getcwd()
    os.chdir(elsewhere)
    try:
        cli.main([http_server(MockHandler), "--yes", "--no-color", "--config", str(config), "--json", str(out)])
    finally:
        os.chdir(cwd)
    assert json.loads(out.read_text(encoding="utf-8"))["api"]["endpoint_count"] == 3


def test_a_bad_spec_named_in_the_config_names_the_config_and_the_key(tmp_path, capsys):
    config = tmp_path / "scanner.toml"
    config.write_text('api_spec = "nope.json"\n', encoding="utf-8")
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["https://t.example/", "--yes", "--config", str(config)])
    assert exit_info.value.code == 2
    err = capsys.readouterr().err
    assert "scanner.toml" in err and "api_spec" in err


def test_the_command_line_wins_over_the_config_file(http_server, tmp_path, spec_file):
    other = tmp_path / "other.json"
    other.write_text(json.dumps(dict(SPEC, info={"title": "From the command line", "version": "1"})), encoding="utf-8")
    config = tmp_path / "scanner.toml"
    config.write_text('api_spec = "api.json"\nchecks = ["headers"]\n', encoding="utf-8")
    data = report_of(http_server(MockHandler), tmp_path, "--config", str(config), "--api-spec", str(other))
    assert data["api"]["title"] == "From the command line"


# --- one pipeline for the CLI and the web UI ---


def test_the_inventory_goes_through_build_report_like_everything_else(spec_file):
    inv = inventory.build_inventory(spec_file)
    result = ScanResult(target="https://t.example/", started_at="2026-01-01T00:00:00Z")
    result.api = inv
    assert output.build_report(result)["api"] == inv.to_dict(redact=redact)
    assert (
        output.build_report(ScanResult(target="https://t.example/", started_at="2026-01-01T00:00:00Z"))["api"] is None
    )


def test_the_web_ui_answers_with_the_field_set_to_null_and_refuses_a_spec_field(http_server):
    server = web.build_server("127.0.0.1", 0, timeout=5)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/api/scan"
        target = http_server(MockHandler)
        data = requests.post(url, json={"target": target, "authorized": True, "checks": ["headers"]}, timeout=60).json()
        assert data["api"] is None
        refused = requests.post(url, json={"target": target, "authorized": True, "api_spec": "/etc/passwd"}, timeout=60)
        assert refused.status_code == 400 and refused.json()["code"] == "unknown_field"
    finally:
        server.shutdown()
        server.server_close()
