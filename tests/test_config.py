"""FR-CI-06: one TOML file for every option; the command line overrides it."""

from __future__ import annotations

import json

import pytest
from conftest import QuietHandler

from websec_scanner import cli
from websec_scanner.config import ConfigError, load_config


class Recording(QuietHandler):
    received: list[dict] = []

    def do_GET(self):
        type(self).received.append({"path": self.path, **dict(self.headers)})
        self.send(200, b"home")


@pytest.fixture
def site(http_server):
    Recording.received = []
    return http_server(Recording)


@pytest.fixture
def config(tmp_path):
    def write(text: str, name: str = "scanner.toml") -> str:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    return write


# --- loading ---------------------------------------------------------------------


def test_a_full_config_loads(config):
    values, warnings = load_config(
        config(
            'targets = ["https://a.example/"]\nfail_on = "medium"\nchecks = ["headers", "tls"]\n'
            "timeout = 5\nrate_limit = 2.5\nmax_requests = 100\ndefault_excludes = false\n"
            '[headers]\n"X-Env" = "staging"\n'
        ),
        environ={},
    )
    assert values["targets"] == ["https://a.example/"]
    assert values["fail_on"] == "medium" and values["checks"] == ["headers", "tls"]
    assert values["timeout"] == 5 and values["rate_limit"] == 2.5 and values["max_requests"] == 100
    assert values["default_excludes"] is False
    assert values["headers"] == {"X-Env": "staging"}
    assert warnings == []


@pytest.mark.parametrize(
    "text, message",
    [
        ("tiemout = 5\n", "unknown key"),  # a typo must not be silently ignored
        ('timeout = "5"\n', "timeout"),
        ("rate_limit = true\n", "rate_limit"),
        ('checks = "headers"\n', "checks"),
        ("headers = 3\n", "headers"),
        ("show_secrets = true\n", "command line"),  # never from a shared file
        ("yes = true\n", "command line"),  # consent is per run
        ("quiet = true\nverbose = true\n", "quiet"),
        ("this is not toml", "not valid TOML"),
    ],
)
def test_an_invalid_config_is_rejected_with_the_reason(config, text, message):
    with pytest.raises(ConfigError, match=message):
        load_config(config(text), environ={})


def test_a_missing_config_file_is_a_clear_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(str(tmp_path / "nope.toml"), environ={})


# --- secrets from the environment ----------------------------------------------------


def test_env_references_are_expanded(config):
    values, warnings = load_config(
        config('[headers]\nAuthorization = "Bearer ${SCAN_TOKEN}"\n[cookies]\nsession = "${SCAN_SESSION}"\n'),
        environ={"SCAN_TOKEN": "fake-token-from-env", "SCAN_SESSION": "fake-session-env"},
    )
    assert values["headers"] == {"Authorization": "Bearer fake-token-from-env"}
    assert values["cookies"] == {"session": "fake-session-env"}
    assert warnings == []


def test_a_missing_env_variable_is_an_error_not_an_empty_string(config):
    with pytest.raises(ConfigError, match="SCAN_TOKEN"):
        load_config(config('[headers]\nAuthorization = "Bearer ${SCAN_TOKEN}"\n'), environ={})


@pytest.mark.parametrize(
    "text",
    [
        '[headers]\nAuthorization = "Bearer literal-token"\n',
        '[cookies]\nsession = "literal-cookie"\n',
        'proxy = "http://user:literal-pass@proxy.example:3128"\n',
    ],
)
def test_a_credential_written_into_the_file_triggers_a_warning(config, text):
    _, warnings = load_config(config(text), environ={})
    assert warnings and "${" in warnings[0]  # the warning says how to fix it


def test_a_harmless_literal_header_triggers_no_warning(config):
    _, warnings = load_config(config('[headers]\n"X-Env" = "staging"\n'), environ={})
    assert warnings == []


# --- paths ---------------------------------------------------------------------------


def test_paths_are_relative_to_the_config_file_not_the_working_directory(tmp_path, config):
    sub = tmp_path / "ci"
    sub.mkdir()
    path = sub / "scanner.toml"
    path.write_text('suppressions = "ignore.toml"\noutput_dir = "reports"\n', encoding="utf-8")
    values, _ = load_config(str(path), environ={})
    assert values["suppressions"] == str(sub / "ignore.toml")
    assert values["output_dir"] == str(sub / "reports")


# --- through the CLI -----------------------------------------------------------------


def test_the_config_drives_a_scan(site, config, tmp_path, capsys):
    out = tmp_path / "r.json"
    path = config(f'targets = ["{site}"]\nchecks = ["headers"]\nfail_on = "none"\njson = "{out.as_posix()}"\n'
                  '[headers]\n"X-Env" = "from-config"\n')  # fmt: skip
    code = cli.main(["--config", path, "--yes", "--no-color"])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 0 and report["scan_groups"] == ["headers"]
    assert Recording.received[0]["X-Env"] == "from-config"


def test_the_command_line_overrides_the_config(site, config, tmp_path, capsys):
    out = tmp_path / "r.json"
    path = config(f'targets = ["{site}"]\nchecks = ["headers"]\nfail_on = "none"\njson = "{out.as_posix()}"\n')
    cli.main(["--config", path, "--yes", "--no-color", "--fail-on", "low", "--checks", "cookies"])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["gate"]["fail_on"] == "low"
    assert report["scan_groups"] == ["cookies"]


def test_headers_from_the_config_and_the_command_line_are_combined(site, config, capsys):
    path = config(f'targets = ["{site}"]\nchecks = ["headers"]\n[headers]\n"X-From-Config" = "1"\n')
    cli.main(["--config", path, "--yes", "--no-color", "--header", "X-From-Cli: 2"])
    first = Recording.received[0]
    assert first["X-From-Config"] == "1" and first["X-From-Cli"] == "2"


def test_a_bad_config_stops_before_any_request(site, config, capsys):
    path = config(f'targets = ["{site}"]\ntiemout = 5\n')
    with pytest.raises(SystemExit):
        cli.main(["--config", path, "--yes"])
    assert Recording.received == []
    assert "unknown key" in capsys.readouterr().err


def test_every_command_line_option_has_a_config_key():
    # FR-CI-06 done-when: anything you can say on the command line you can say in the file,
    # except the options that must stay a per-run decision on the command line.
    per_run_only = {"config", "show_secrets", "assume_yes", "list_checks", "version", "help", "target"}
    from websec_scanner.config import CONFIG_KEYS

    destinations = {a.dest for a in cli.build_parser()._actions} - per_run_only
    covered = {CONFIG_KEYS[key] for key in CONFIG_KEYS}
    assert destinations <= covered, sorted(destinations - covered)
