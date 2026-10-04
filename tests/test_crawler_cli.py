"""FR-CRAWL-01/04 at the command line, in the config file, in every report format, and in the web UI."""

from __future__ import annotations

import csv
import io
import json
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

import jsonschema
import pytest
import requests
from crawl_site import Page, html, site_handler

from websec_scanner import cli, web
from websec_scanner.models import SCHEMA_VERSION

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "report.schema.json"

PAGES = {
    "/": Page(html("/a", "/b"), headers={"X-Frame-Options": "DENY"}),
    "/a": Page(html()),
    "/b": Page(html()),
}


def scan(http_server, tmp_path, *args, pages=PAGES, formats=("json",)):
    base = http_server(site_handler(pages))
    out = {fmt: tmp_path / f"report.{fmt}" for fmt in formats}
    flags = [f"--{fmt}={path}" for fmt, path in out.items()]
    code = cli.main([base, "--yes", "--no-color", "--no-tls-probe", *flags, *args])
    return code, base, out


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_crawl_flag_adds_pages_and_the_report_says_so(http_server, tmp_path):
    code, base, out = scan(http_server, tmp_path, "--crawl")
    report = load(out["json"])
    assert report["schema_version"] == SCHEMA_VERSION == "1.11"
    assert report["crawl"]["pages_visited"] == 3
    assert report["crawl"]["stopped_reason"] == "complete"
    csp = next(f for f in report["findings"] if f["id"] == "HDR-CONTENT-SECURITY-POLICY-MISSING")
    assert csp["affected_urls"] == [base, base + "a", base + "b"] and csp["affected_count"] == 3
    assert code == cli.main(
        [base, "--yes", "--no-color", "--no-tls-probe", "--quiet"]
    )  # a crawl alone does not change it


def test_without_crawl_the_report_has_crawl_null_and_one_url_per_finding(http_server, tmp_path):
    _, base, out = scan(http_server, tmp_path)
    report = load(out["json"])
    assert report["crawl"] is None
    assert all(f["affected_count"] == (1 if f["url"] else 0) for f in report["findings"])


def test_the_json_report_matches_the_schema(http_server, tmp_path):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for extra in ([], ["--crawl", "--crawl-depth", "1"]):
        _, _, out = scan(http_server, tmp_path, *extra)
        validator.validate(load(out["json"]))


def test_the_schema_rejects_a_malformed_crawl_object(http_server, tmp_path):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    _, _, out = scan(http_server, tmp_path, "--crawl")
    report = load(out["json"])
    for mutate in (
        lambda r: r["crawl"].pop("stopped_reason"),
        lambda r: r["crawl"].update(stopped_reason="because"),
        lambda r: r["crawl"].update(pages_visited=0),
        lambda r: r["crawl"].update(extra=1),
        lambda r: r.pop("crawl"),
        lambda r: r["findings"][0].pop("affected_urls"),
        lambda r: r["findings"][0].update(affected_count=-1),
    ):
        broken = json.loads(json.dumps(report))
        mutate(broken)
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(broken)


def test_the_limits_are_options(http_server, tmp_path):
    _, _, out = scan(http_server, tmp_path, "--crawl", "--crawl-depth", "1", "--crawl-max-pages", "2")
    crawl = load(out["json"])["crawl"]
    assert (crawl["max_depth"], crawl["max_pages"]) == (1, 2)
    assert crawl["pages_visited"] == 2 and crawl["stopped_reason"] == "max-pages"


def test_crawl_duration_option_is_recorded(http_server, tmp_path):
    _, _, out = scan(http_server, tmp_path, "--crawl", "--crawl-max-duration", "12.5")
    assert load(out["json"])["crawl"]["max_duration"] == 12.5


def test_ignore_robots_is_explicit(http_server, tmp_path):
    pages = {**PAGES, "/robots.txt": Page("User-agent: *\nDisallow: /a\n", content_type="text/plain")}
    _, _, respected = scan(http_server, tmp_path, "--crawl", pages=pages)
    assert load(respected["json"])["crawl"]["skipped"] == {"robots-disallowed": 1}
    _, _, ignored = scan(http_server, tmp_path, "--crawl", "--ignore-robots", pages=pages)
    crawl = load(ignored["json"])["crawl"]
    assert crawl["respect_robots"] is False and crawl["pages_visited"] == 3 and crawl["skipped"] == {}


@pytest.mark.parametrize(
    "flags",
    [
        ["--crawl-depth", "2"],
        ["--crawl-max-pages", "10"],
        ["--crawl-max-duration", "5"],
        ["--ignore-robots"],
    ],
)
def test_a_crawl_setting_without_crawl_is_an_error_before_any_request(http_server, tmp_path, capsys, flags):
    handler = site_handler(PAGES)
    base = http_server(handler)
    with pytest.raises(SystemExit) as exc:
        cli.main([base, "--yes", *flags])
    assert exc.value.code == 2
    assert "--crawl" in capsys.readouterr().err
    assert handler.hits == []


@pytest.mark.parametrize(
    "flags",
    [
        ["--crawl", "--crawl-depth", "-1"],
        ["--crawl", "--crawl-depth", "x"],
        ["--crawl", "--crawl-max-pages", "0"],
        ["--crawl", "--crawl-max-duration", "0"],
    ],
)
def test_bad_crawl_values_are_refused_before_any_request(http_server, flags):
    handler = site_handler(PAGES)
    base = http_server(handler)
    with pytest.raises(SystemExit) as exc:
        cli.main([base, "--yes", *flags])
    assert exc.value.code == 2
    assert handler.hits == []


def test_depth_zero_is_allowed_and_means_the_home_page_only(http_server, tmp_path):
    _, _, out = scan(http_server, tmp_path, "--crawl", "--crawl-depth", "0")
    crawl = load(out["json"])["crawl"]
    assert crawl["pages_visited"] == 1 and crawl["stopped_reason"] == "max-depth"


def test_the_operator_is_told_what_a_crawl_costs_before_confirming(http_server, tmp_path, capsys):
    scan(http_server, tmp_path, "--crawl", "--crawl-max-pages", "7")
    out = capsys.readouterr().out
    notice = out.split("Scanning")[0]  # before the scan starts, so before the operator confirms
    assert "Crawl enabled (--crawl): up to 7 pages, 2 link level(s) deep" in notice
    assert "robots.txt is read first and its rules are followed" in notice
    scan(http_server, tmp_path)
    assert "Crawl enabled" not in capsys.readouterr().out


def test_the_notice_says_when_robots_txt_is_ignored(http_server, tmp_path, capsys):
    scan(http_server, tmp_path, "--crawl", "--ignore-robots")
    assert "ignored" in capsys.readouterr().out.lower()


def test_quiet_with_yes_prints_no_notice(http_server, tmp_path, capsys):
    scan(http_server, tmp_path, "--crawl", "--quiet")
    assert "Crawl enabled" not in capsys.readouterr().out


def test_the_console_report_shows_the_crawl_and_the_other_pages(http_server, tmp_path, capsys):
    scan(http_server, tmp_path, "--crawl")
    out = capsys.readouterr().out
    assert "Crawl: 3 page(s)" in out
    assert "Seen on 3 pages: " in out  # the CSP finding is on all three pages; the others are named
    assert "other page(s)" not in out  # all of them fit on the line


def test_the_console_names_five_other_pages_and_counts_the_rest(http_server, tmp_path, capsys):
    pages = {"/": Page(html(*[f"/p{n}" for n in range(8)])), **{f"/p{n}": Page(html()) for n in range(8)}}
    scan(http_server, tmp_path, "--crawl", pages=pages)
    out = capsys.readouterr().out
    assert "Seen on 9 pages: " in out and "and 3 other page(s)" in out


def test_the_console_names_why_a_crawl_stopped_early(http_server, tmp_path, capsys):
    scan(http_server, tmp_path, "--crawl", "--crawl-max-pages", "2")
    out = capsys.readouterr().out
    assert "stopped at --crawl-max-pages" in out


def test_console_text_from_crawled_pages_cannot_carry_escape_sequences(http_server, tmp_path, capsys):
    pages = {"/": Page(html("/a?x=\x1b[2Jevil")), "/a": Page(html())}  # a real ESC character in the link
    scan(http_server, tmp_path, "--crawl", pages=pages)
    out = capsys.readouterr().out
    assert "\x1b[2J" not in out  # nothing a terminal would act on
    assert "\\x1b[2Jevil" in out  # the link is still shown, with the character made visible


def test_html_report_lists_the_pages_a_finding_was_seen_on(http_server, tmp_path):
    _, base, out = scan(http_server, tmp_path, "--crawl", formats=("html",))
    text = out["html"].read_text(encoding="utf-8")
    assert "Also seen on" in text and base + "b" in text
    assert "Crawl" in text


def test_html_report_escapes_crawled_urls(http_server, tmp_path):
    pages = {"/": Page(html("/a?x=<script>alert(1)</script>")), "/a": Page(html())}
    _, _, out = scan(http_server, tmp_path, "--crawl", pages=pages, formats=("html",))
    text = out["html"].read_text(encoding="utf-8")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text  # the URL is there, as text
    assert "<script>alert(1)</script>" not in text


def test_sarif_has_a_location_for_each_page(http_server, tmp_path):
    _, base, out = scan(http_server, tmp_path, "--crawl", formats=("sarif",))
    results = load(out["sarif"])["runs"][0]["results"]
    csp = next(r for r in results if r["ruleId"] == "HDR-CONTENT-SECURITY-POLICY-MISSING")
    uris = [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in csp["locations"]]
    assert uris == [base, base + "a", base + "b"]
    other = next(r for r in results if r["ruleId"] == "HDR-X-FRAME-OPTIONS-MISSING")
    assert len(other["locations"]) == 2


def test_csv_has_the_number_of_pages(http_server, tmp_path):
    _, _, out = scan(http_server, tmp_path, "--crawl", formats=("csv",))
    rows = list(csv.DictReader(io.StringIO(out["csv"].read_text(encoding="utf-8"))))
    csp = next(r for r in rows if r["id"] == "HDR-CONTENT-SECURITY-POLICY-MISSING")
    assert csp["affected_count"] == "3"
    assert list(rows[0]).index("affected_count") == list(rows[0]).index("url") + 1
    assert list(rows[0])[-1] == "fingerprint"  # the columns that were there keep their order


def test_junit_mentions_the_extra_pages(http_server, tmp_path):
    _, _, out = scan(http_server, tmp_path, "--crawl", "--fail-on", "low", formats=("junit",))
    root = ET.fromstring(out["junit"].read_text(encoding="utf-8"))  # noqa: S314 - parses the scanner's own output
    messages = " ".join((el.get("message") or "") + (el.text or "") for el in root.iter("failure"))
    assert "2 other page" in messages


def test_the_config_file_can_turn_the_crawl_on(http_server, tmp_path):
    config = tmp_path / "scanner.toml"
    config.write_text("crawl = true\ncrawl_depth = 1\ncrawl_max_pages = 9\nignore_robots = true\n", encoding="utf-8")
    _, _, out = scan(http_server, tmp_path, "--config", str(config))
    crawl = load(out["json"])["crawl"]
    assert (crawl["max_depth"], crawl["max_pages"], crawl["respect_robots"]) == (1, 9, False)


def test_the_command_line_wins_over_the_config_file(http_server, tmp_path):
    config = tmp_path / "scanner.toml"
    config.write_text("crawl = true\ncrawl_depth = 1\n", encoding="utf-8")
    _, _, out = scan(http_server, tmp_path, "--config", str(config), "--crawl-depth", "0")
    assert load(out["json"])["crawl"]["max_depth"] == 0


def test_a_config_crawl_setting_without_crawl_is_refused(tmp_path, capsys):
    config = tmp_path / "scanner.toml"
    config.write_text("crawl_depth = 3\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cli.main(["http://127.0.0.1:1/", "--yes", "--config", str(config)])
    assert exc.value.code == 2
    assert "crawl" in capsys.readouterr().err


@pytest.mark.parametrize("line", ["crawl = 1", "crawl_depth = -2", "crawl_max_pages = 0", 'crawl_depth = "2"'])
def test_bad_config_values_are_refused(tmp_path, capsys, line):
    config = tmp_path / "scanner.toml"
    config.write_text(f"crawl = true\n{line}\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cli.main(["http://127.0.0.1:1/", "--yes", "--config", str(config)])
    assert exc.value.code == 2


def test_the_crawl_applies_to_every_target(http_server, tmp_path):
    one, two = http_server(site_handler(PAGES)), http_server(site_handler(PAGES))
    out_dir = tmp_path / "reports"
    cli.main([one, two, "--yes", "--no-color", "--no-tls-probe", "--crawl", "--output-dir", str(out_dir)])
    reports = [load(path) for path in sorted(out_dir.glob("*.json"))]
    assert len(reports) == 2 and all(r["crawl"]["pages_visited"] == 3 for r in reports)


# --- the web UI never crawls ---------------------------------------------------------------------


@pytest.fixture
def ui():
    server = web.build_server("127.0.0.1", 0, timeout=5)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_the_web_ui_refuses_every_crawl_setting(ui):
    """The crawl box itself is `crawl` (tests/test_web_crawl.py); its settings are not the browser's to send."""
    for field_name in ("crawl_depth", "crawl_max_pages", "crawl_max_duration", "ignore_robots"):
        response = requests.post(
            ui + "/api/scan",
            json={"target": "http://127.0.0.1:9/", "authorized": True, field_name: True},
            timeout=5,
        )
        assert response.status_code == 400
        assert response.json()["code"] == "unknown_field"
