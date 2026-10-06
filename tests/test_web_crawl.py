"""FR-UI-14: the local web UI can crawl, when the user ticks the box, within limits the operator chose.

The browser sends one boolean. The limits (depth, pages, time) are set when the server starts, like
--rate-limit and --max-requests, and the web UI always follows robots.txt: none of that can be
changed from the page, and every other crawl field is still refused.
"""

from __future__ import annotations

import threading

import pytest
import requests
from crawl_site import Page, html, site_handler

from websec_scanner import web
from websec_scanner.crawler.crawl import CrawlOptions

PAGES = {
    "/": Page(html("/a", "/b"), headers={"X-Frame-Options": "DENY"}),
    "/a": Page(html()),
    "/b": Page(html()),
}


@pytest.fixture
def ui_factory():
    servers = []

    def make(**options):
        server = web.build_server("127.0.0.1", 0, timeout=5, tls_probe=False, **options)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield make
    for server in servers:
        server.shutdown()
        server.server_close()


def scan(ui, target, **extra):
    return requests.post(f"{ui}/api/scan", json={"target": target, "authorized": True, **extra}, timeout=120)


@pytest.fixture
def no_scan(monkeypatch):
    monkeypatch.setattr(web, "run_scan", lambda *a, **kw: pytest.fail("a rejected request started a scan"))


# --- what the page is told ----------------------------------------------------------------------


def test_the_checks_list_also_tells_the_page_the_crawl_limits(ui_factory):
    ui = ui_factory()
    data = requests.get(f"{ui}/api/checks", timeout=5).json()
    assert data["crawl"] == {"max_depth": 2, "max_pages": 50, "max_duration": 60.0}
    assert [g["id"] for g in data["groups"]][:2] == ["headers", "cookies"]  # the list itself is unchanged


def test_the_limits_the_page_is_told_are_the_ones_the_server_uses(ui_factory):
    ui = ui_factory(crawl_options=CrawlOptions(max_depth=1, max_pages=7, max_duration=12.5))
    assert requests.get(f"{ui}/api/checks", timeout=5).json()["crawl"] == {
        "max_depth": 1,
        "max_pages": 7,
        "max_duration": 12.5,
    }


# --- crawl on and off ------------------------------------------------------------------------------


def test_without_the_box_only_the_target_page_is_scanned(ui_factory, http_server):
    handler = site_handler(PAGES)
    base = http_server(handler)
    for extra in ({}, {"crawl": False}):
        data = scan(ui_factory(), base, **extra).json()
        assert data["crawl"] is None and data["crawl_message"] is None
    assert "/a" not in handler.hits and "/b" not in handler.hits


def test_with_the_box_the_linked_pages_are_scanned_too(ui_factory, http_server):
    handler = site_handler(PAGES)
    base = http_server(handler)
    data = scan(ui_factory(), base, crawl=True).json()
    assert "/a" in handler.hits and "/b" in handler.hits
    assert data["crawl"]["pages_visited"] == 3 and data["crawl"]["stopped_reason"] == "complete"
    csp = next(f for f in data["findings"] if f["id"] == "HDR-CONTENT-SECURITY-POLICY-MISSING")
    assert csp["affected_urls"] == [base, base + "a", base + "b"] and csp["affected_count"] == 3


def test_the_report_says_in_words_what_the_crawl_did(ui_factory, http_server):
    data = scan(ui_factory(), http_server(site_handler(PAGES)), crawl=True).json()
    assert data["crawl_message"] == "3 page(s) visited: all reachable pages were visited"
    assert "crawl_message" in web.WEB_ONLY_FIELDS


def test_the_download_has_the_crawl_card(ui_factory, http_server):
    ui = ui_factory()
    data = scan(ui, http_server(site_handler(PAGES)), crawl=True).json()
    report = requests.get(ui + data["report_url"], timeout=5).text
    assert "<h2>Crawl</h2>" in report and "Also seen on" in report


def pairs(report):
    return sorted((f["id"], f["affected_count"]) for f in report["findings"])


def test_the_crawl_is_the_same_json_as_the_cli(ui_factory, http_server):
    from websec_scanner import cli, output

    base = http_server(site_handler(PAGES))
    data = scan(ui_factory(), base, crawl=True).json()
    cli_report = output.build_report(cli.run_scan(base, tls_probe=False, crawl=CrawlOptions()))
    assert data["crawl"] == cli_report["crawl"]
    assert pairs(data) == pairs(cli_report)


# --- what the browser cannot do -------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["yes", "true", 1, 0, None, [], {}, ["a"]])
def test_crawl_must_be_a_json_boolean(ui_factory, no_scan, value):
    response = scan(ui_factory(), "http://127.0.0.1:9/", crawl=value)
    assert response.status_code == 400
    assert response.json()["error"] == "crawl must be true or false"


@pytest.mark.parametrize(
    "field",
    [
        "crawl_depth",
        "crawl_max_pages",
        "crawl_max_duration",
        "ignore_robots",
        "crawl-depth",
        "crawlDepth",
        "ignoreRobots",
    ],
)
def test_every_other_crawl_field_is_still_refused(ui_factory, no_scan, field):
    response = scan(ui_factory(), "http://127.0.0.1:9/", crawl=True, **{field: 1})
    assert response.status_code == 400
    assert response.json()["code"] == "unknown_field" and response.json()["field"] == field


def test_the_refusal_names_crawl_among_the_accepted_fields(ui_factory, no_scan):
    message = scan(ui_factory(), "http://127.0.0.1:9/", extra=1).json()["error"]
    assert "Accepted fields: authorized, checks, crawl, target." in message


def test_a_credential_is_still_refused_next_to_the_crawl_box(ui_factory, no_scan):
    response = scan(ui_factory(), "http://127.0.0.1:9/", crawl=True, cookie="a=b")
    assert response.status_code == 400 and response.json()["code"] == "credential_not_accepted"


def test_the_browser_cannot_lift_the_servers_page_limit(ui_factory, http_server):
    pages = {"/": Page(html(*[f"/p{n}" for n in range(6)])), **{f"/p{n}": Page(html()) for n in range(6)}}
    handler = site_handler(pages)
    base = http_server(handler)
    ui = ui_factory(crawl_options=CrawlOptions(max_pages=3))
    data = scan(ui, base, crawl=True).json()
    assert data["crawl"]["pages_visited"] == 3 and data["crawl"]["stopped_reason"] == "max-pages"
    assert scan(ui, base, crawl=True, crawl_max_pages=100).status_code == 400  # asking for more is refused


def test_the_web_ui_always_follows_robots_txt(ui_factory, http_server):
    pages = {**PAGES, "/robots.txt": Page("User-agent: *\nDisallow: /a\n", content_type="text/plain")}
    handler = site_handler(pages)
    data = scan(ui_factory(), http_server(handler), crawl=True).json()
    assert data["crawl"]["respect_robots"] is True and data["crawl"]["skipped"] == {"robots-disallowed": 1}
    assert "/a" not in handler.hits


def test_the_servers_request_cap_applies_to_the_crawl_too(ui_factory, http_server):
    handler = site_handler(PAGES)
    base = http_server(handler)
    plain = scan(ui_factory(), base).json()["limits"]["requests_sent"]
    data = scan(ui_factory(max_requests=plain + 2), base, crawl=True).json()
    assert data["limits"]["stopped_by"] == "max-requests"
    assert data["crawl"]["stopped_reason"] == "scan-limit"


def test_a_crawl_with_no_page_check_selected_says_it_was_ignored(ui_factory, http_server):
    handler = site_handler(PAGES)
    data = scan(ui_factory(), http_server(handler), crawl=True, checks=["exposed-files"]).json()
    assert data["crawl"] is None and "/a" not in handler.hits
    assert any("ignored" in error for error in data["errors"])


# --- the server's own options ---------------------------------------------------------------------------


def test_the_server_options_build_the_crawl_limits():
    options = web._crawl_options_from(web.build_parser().parse_args(["--crawl-depth", "0", "--crawl-max-pages", "9"]))
    assert (options.max_depth, options.max_pages, options.max_duration, options.respect_robots) == (0, 9, 60.0, True)
    defaults = web._crawl_options_from(web.build_parser().parse_args([]))
    assert defaults == CrawlOptions()


@pytest.mark.parametrize(
    "flags",
    [["--crawl-depth", "-1"], ["--crawl-depth", "x"], ["--crawl-max-pages", "0"], ["--crawl-max-duration", "0"]],
)
def test_bad_server_crawl_options_are_refused_at_start(flags, capsys):
    with pytest.raises(SystemExit) as exc:
        web.main(flags)
    assert exc.value.code == 2


def test_there_is_no_ignore_robots_option_for_the_server(capsys):
    with pytest.raises(SystemExit) as exc:
        web.main(["--ignore-robots"])
    assert exc.value.code == 2


def test_main_hands_the_crawl_limits_to_the_server(monkeypatch):
    seen = {}

    class Stub:
        loopback_only = True
        server_address = ("127.0.0.1", 1)

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            pass

    def fake_build_server(**kwargs):
        seen.update(kwargs)
        return Stub()

    monkeypatch.setattr(web, "build_server", fake_build_server)
    assert web.main(["--crawl-depth", "1", "--crawl-max-pages", "9", "--crawl-max-duration", "30"]) == 0
    assert seen["crawl_options"] == CrawlOptions(max_depth=1, max_pages=9, max_duration=30.0)
    seen.clear()
    assert web.main([]) == 0
    assert seen["crawl_options"] == CrawlOptions()


def test_depth_zero_is_a_valid_server_option():
    args = web.build_parser().parse_args(["--crawl-depth", "0"])
    assert web._crawl_options_from(args).max_depth == 0


def test_the_crawl_box_is_in_the_page_and_off_by_default():
    import re
    from pathlib import Path

    page = (Path(web.__file__).with_name("static") / "index.html").read_text(encoding="utf-8")
    box = re.search(r'<input[^>]*id="crawl"[^>]*>', page)
    assert box, "the crawl checkbox is missing from the page"
    assert 'type="checkbox"' in box.group(0)
    assert "checked" not in box.group(0)  # a scan only crawls when the user chose it
    assert "Also crawl the site and check the pages it links to" in page
