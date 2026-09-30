"""Test-target groups: one declarative table, selectable per scan (Sprint 8)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import QuietHandler
from mock_server import Handler as MockHandler

from owasp_scanner import catalog, cli, output

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "docs" / "report.schema.json").read_text("utf-8"))
ALL_CHECKS = SCHEMA["properties"]["checks_run"]["items"]["enum"]


class RecordingMock(MockHandler):
    """The mock server, remembering every path it was asked for."""

    paths: list[str] = []

    def do_GET(self):
        type(self).paths.append(self.path.split("?")[0])
        super().do_GET()


@pytest.fixture
def recording_mock(http_server):
    class Handler(RecordingMock):
        paths: list[str] = []

    return http_server(Handler), Handler.paths


def test_every_check_belongs_to_exactly_one_group():
    owners = [check for group in catalog.CHECK_GROUPS for check in group.checks]
    assert sorted(owners) == sorted(ALL_CHECKS)
    assert len({g.id for g in catalog.CHECK_GROUPS}) == len(catalog.CHECK_GROUPS)
    assert all(g.title and g.description for g in catalog.CHECK_GROUPS)


def test_group_ids_are_stable():
    assert catalog.GROUP_IDS == (
        "headers",
        "cookies",
        "tls",
        "https-redirect",
        "cors",
        "exposed-files",
        "directory-listing",
        "robots-sitemap",
    )


def test_default_scan_runs_every_group_and_tags_each_finding(recording_mock):
    target, _ = recording_mock
    report = output.build_report(cli.run_scan(target, timeout=5))
    assert report["scan_groups"] == list(catalog.GROUP_IDS)
    assert report["findings"]
    for finding in report["findings"]:
        assert finding["check"] in report["checks_run"]
        assert catalog.group_of_check(finding["check"]) in catalog.GROUP_IDS


def test_only_the_selected_groups_run_and_send_requests(recording_mock):
    target, paths = recording_mock
    report = output.build_report(cli.run_scan(target, timeout=5, groups=["headers", "cookies"]))
    assert report["scan_groups"] == ["headers", "cookies"]
    assert report["checks_run"] == ["security-headers", "cookies"]
    assert {f["check"] for f in report["findings"]} == {"security-headers", "cookies"}
    assert paths == ["/"]  # the baseline only: no probe, path, robots or CORS request


def test_selected_groups_are_reported_in_table_order(recording_mock):
    target, _ = recording_mock
    result = cli.run_scan(target, timeout=5, groups=["robots-sitemap", "headers"])
    assert result.scan_groups == ["headers", "robots-sitemap"]


def test_directory_listing_alone_still_uses_the_soft404_probes(recording_mock):
    target, paths = recording_mock
    cli.run_scan(target, timeout=5, groups=["directory-listing"])
    assert any(p.startswith("/owasp-scanner-probe-") for p in paths)
    assert "/.env" not in paths and "/robots.txt" not in paths


def test_gate_counts_only_the_selected_groups(recording_mock):
    target, _ = recording_mock
    # The mock has CRITICAL exposed files; without that group the HIGH redirect finding remains.
    report = output.build_report(cli.run_scan(target, timeout=5, groups=["cookies"]))
    assert report["summary"]["CRITICAL"] == 0 and report["summary"]["HIGH"] == 0
    assert report["gate"]["failed"] is False


@pytest.mark.parametrize("groups, message", [([], "at least one"), (["headers", "nope"], "nope")])
def test_invalid_group_selection_is_rejected(groups, message):
    with pytest.raises(ValueError, match=message):
        catalog.normalize_groups(groups)


def test_group_selection_ignores_duplicates_and_case():
    assert catalog.normalize_groups(["TLS", "headers", "tls"]) == ["headers", "tls"]


def test_unreachable_target_still_records_the_selection(closed_port):
    result = cli.run_scan(f"http://127.0.0.1:{closed_port}/", timeout=2, groups=["cors"])
    assert result.scan_groups == ["cors"] and result.checks_run == []


class _PlainHttp(QuietHandler):
    def do_GET(self):
        self.send(200, b"ok", {"Content-Type": "text/plain"})


def test_https_redirect_group_alone_on_an_http_target(http_server):
    result = cli.run_scan(http_server(_PlainHttp), timeout=5, groups=["https-redirect"])
    assert result.checks_run == ["http-to-https-redirect"]
    assert [f.id for f in result.findings] == ["TLS-NO-HTTPS-REDIRECT"]


# --- CLI: --checks and --list-checks ------------------------------------------------


def test_list_checks_prints_every_group_without_a_target(capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("--list-checks must not ask for authorization"))
    assert cli.main(["--list-checks"]) == 0
    out = capsys.readouterr().out
    for group in catalog.CHECK_GROUPS:
        assert group.id in out and group.title in out


def test_checks_option_selects_groups(recording_mock, tmp_path, capsys):
    target, paths = recording_mock
    out = tmp_path / "r.json"
    cli.main([target, "--yes", "--no-color", "--checks", "cookies,HEADERS", "--json", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["scan_groups"] == ["headers", "cookies"] and paths == ["/"]
    console = capsys.readouterr().out
    assert "Check groups: Security headers, Cookies" in console
    assert "Not selected (not tested): TLS/SSL, HTTP to HTTPS redirect" in console


def test_console_does_not_list_unselected_groups_for_a_full_scan(recording_mock, capsys):
    target, _ = recording_mock
    cli.main([target, "--yes", "--no-color"])
    assert "Not selected" not in capsys.readouterr().out


@pytest.mark.parametrize("argv, message", [(["t.example", "--checks", "tls,bogus"], "bogus"), ([], "target")])
def test_bad_check_selection_or_missing_target_exits_2(capsys, argv, message):
    with pytest.raises(SystemExit) as exc:
        cli.main([*argv, "--yes"])
    assert exc.value.code == 2 and message in capsys.readouterr().err
