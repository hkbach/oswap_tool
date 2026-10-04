"""FR-CRAWL-01 and FR-CRAWL-04: the crawler follows same-origin links, within limits, and says why it stopped.

Every test runs against a local site (tests/crawl_site.py) and reads the site's own request log, so
"the crawler did not ask for X" is checked from the server's side, not assumed.
"""

from __future__ import annotations

import re
import socket
from itertools import count

import pytest
from crawl_site import Page, html, site_handler

from websec_scanner.crawler import crawl as crawl_module
from websec_scanner.crawler.crawl import CrawlOptions, crawl
from websec_scanner.http_utils import build_session
from websec_scanner.limits import ScanLimiter

ROBOTS = "/robots.txt"


def run(http_server, pages, *, session=None, handler=None, clock=None, **options):
    """Crawl the site from its home page; returns ``(result, request log, base URL)``."""
    handler = handler or site_handler(pages)
    base = http_server(handler)
    session = session or build_session(scope_host="127.0.0.1")
    start = session.get(base)
    kwargs = {"clock": clock} if clock else {}
    result = crawl(session, start.url, start.text, CrawlOptions(**options), **kwargs)
    # the first request in the log is the home page, fetched by this helper like run_scan() does
    return result, handler.hits[1:], base


def paths(result):
    return ["/" + page.url.split("/", 3)[3] for page in result.pages]


def test_follows_links_breadth_first_down_to_max_depth(http_server):
    pages = {
        "/": Page(html("/a", "/b")),
        "/a": Page(html("/c")),
        "/b": Page(html()),
        "/c": Page(html("/d")),
        "/d": Page(html()),
    }
    result, hits, _ = run(http_server, pages, max_depth=2)
    assert hits == [ROBOTS, "/a", "/b", "/c"]
    assert paths(result) == ["/a", "/b", "/c"]
    assert [page.depth for page in result.pages] == [1, 1, 2]
    assert result.stopped_reason == "max-depth"
    assert result.skipped["beyond-depth"] == 1  # /d was seen but is one level too deep


def test_a_deeper_limit_reaches_deeper_pages(http_server):
    pages = {"/": Page(html("/a")), "/a": Page(html("/b")), "/b": Page(html("/c")), "/c": Page(html())}
    result, _, _ = run(http_server, pages, max_depth=3)
    assert paths(result) == ["/a", "/b", "/c"]
    assert result.stopped_reason == "complete"
    assert "beyond-depth" not in result.skipped


def test_depth_zero_sends_no_request_at_all(http_server):
    result, hits, _ = run(http_server, {"/": Page(html("/a")), "/a": Page(html())}, max_depth=0)
    assert hits == []  # not even robots.txt: there is nothing to decide about
    assert result.pages == []
    assert result.stopped_reason == "max-depth"


def test_link_cycles_and_self_links_visit_each_page_once(http_server):
    pages = {
        "/": Page(html("/a", "/")),
        "/a": Page(html("/", "/a", "/b#top")),
        "/b": Page(html("/a", "/b")),
    }
    result, hits, _ = run(http_server, pages, max_depth=10)
    assert hits == [ROBOTS, "/a", "/b"]  # the home page, fetched before the crawl, is not fetched again
    assert result.stopped_reason == "complete"


def test_max_pages_counts_the_home_page_and_stops_exactly(http_server):
    pages = {"/": Page(html("/a", "/b", "/c", "/d")), **{p: Page(html()) for p in ("/a", "/b", "/c", "/d")}}
    result, hits, _ = run(http_server, pages, max_pages=3)
    assert hits == [ROBOTS, "/a", "/b"]  # home page + 2 = 3 pages
    assert result.pages_visited == 3
    assert result.stopped_reason == "max-pages"


def test_max_pages_of_one_means_the_home_page_only(http_server):
    result, hits, _ = run(http_server, {"/": Page(html("/a")), "/a": Page(html())}, max_pages=1)
    assert hits == []
    assert result.pages_visited == 1
    assert result.stopped_reason == "max-pages"


def test_max_pages_exactly_enough_is_complete_not_truncated(http_server):
    pages = {"/": Page(html("/a")), "/a": Page(html())}
    result, _, _ = run(http_server, pages, max_pages=2)
    assert result.pages_visited == 2
    assert result.stopped_reason == "complete"


def test_max_duration_stops_before_the_next_page(http_server):
    pages = {"/": Page(html("/a", "/b", "/c", "/d")), **{p: Page(html()) for p in ("/a", "/b", "/c", "/d")}}
    ticks = count(0, 10)  # the fake clock moves 10 s each time the crawler looks at it
    result, hits, _ = run(http_server, pages, max_duration=25, max_depth=5, clock=lambda: next(ticks))
    assert hits == [ROBOTS, "/a", "/b"]  # looked at 10 and 20 (< 25), then at 30
    assert result.stopped_reason == "max-duration"


def test_links_to_another_origin_are_not_requested(http_server):
    other = site_handler({"/": Page(html()), "/x": Page(html())})
    other_base = http_server(other)
    pages = {"/": Page(html("/a", other_base + "x", "https://127.0.0.1/y", "http://localhost:1/z")), "/a": Page(html())}
    result, hits, _ = run(http_server, pages)
    assert hits == [ROBOTS, "/a"]
    assert other.hits == []  # same host name, different port: another origin
    assert result.skipped["other-origin"] == 3


def test_a_link_back_with_another_spelling_of_the_same_origin_is_followed(http_server):
    pages = {"/": Page(html("/a")), "/a": Page(html())}
    handler = site_handler(pages)
    base = http_server(handler)
    host_port = base.split("//")[1].rstrip("/")
    session = build_session(scope_host="127.0.0.1")
    start = session.get(base)
    page_html = html(f"http://{host_port.upper()}/a", f"http://{host_port}/a?")
    result = crawl(session, start.url, page_html, CrawlOptions())
    assert paths(result) == ["/a"]  # upper-case host and an empty query are the same page


def test_a_redirect_inside_the_origin_is_followed_by_the_crawler(http_server):
    pages = {
        "/": Page(html("/old")),
        "/old": Page(status=302, headers={"Location": "/new"}),
        "/new": Page(html("/deeper")),
        "/deeper": Page(html()),
    }
    result, hits, _ = run(http_server, pages, max_depth=3)
    assert hits == [ROBOTS, "/old", "/new", "/deeper"]
    assert "/new" in paths(result)
    old = next(page for page in result.pages if page.url.endswith("/old"))
    assert old.status == 302 and not old.checkable  # a redirect response is not a page to judge


def test_a_redirect_target_is_at_the_depth_of_the_page_that_redirected(http_server):
    pages = {
        "/": Page(html("/old")),
        "/old": Page(status=302, headers={"Location": "/new"}),
        "/new": Page(html("/deeper")),
        "/deeper": Page(html()),
    }
    result, hits, _ = run(http_server, pages, max_depth=1)
    assert hits == [ROBOTS, "/old", "/new"]  # /new is as deep as /old, so one level; /deeper is two
    assert [page.depth for page in result.pages] == [1, 1]


def test_a_redirect_to_another_origin_is_never_requested(http_server):
    other = site_handler({"/": Page(html()), "/landing": Page(html())})
    other_base = http_server(other)
    pages = {"/": Page(html("/out")), "/out": Page(status=302, headers={"Location": other_base + "landing"})}
    result, hits, _ = run(http_server, pages)
    assert hits == [ROBOTS, "/out"]
    assert other.hits == []
    assert result.skipped["other-origin"] == 1


def test_a_redirect_loop_does_not_run_forever(http_server):
    pages = {
        "/": Page(html("/x")),
        "/x": Page(status=302, headers={"Location": "/y"}),
        "/y": Page(status=302, headers={"Location": "/x"}),
    }
    result, hits, _ = run(http_server, pages, max_depth=50)
    assert hits == [ROBOTS, "/x", "/y"]
    assert result.stopped_reason == "complete"


def test_excluded_urls_are_not_requested(http_server):
    pages = {"/": Page(html("/ok", "/logout", "/admin/logout")), "/ok": Page(html()), "/logout": Page(html())}
    session = build_session(scope_host="127.0.0.1", exclusions=[re.compile("logout")])
    result, hits, base = run(http_server, pages, session=session)
    assert hits == [ROBOTS, "/ok"]
    assert result.skipped["excluded"] == 2
    assert base + "logout" in session.excluded_urls  # the report's own "not requested" note still lists them


def test_robots_txt_disallow_is_respected_by_default(http_server):
    pages = {
        ROBOTS: Page("User-agent: *\nDisallow: /private/\n", content_type="text/plain"),
        "/": Page(html("/public", "/private/secret", "/private")),
        "/public": Page(html()),
        "/private/secret": Page(html()),
        "/private": Page(html()),
    }
    result, hits, _ = run(http_server, pages)
    assert hits == [ROBOTS, "/public", "/private"]  # "/private" without the slash is not under "/private/"
    assert result.skipped["robots-disallowed"] == 1


def test_robots_txt_rules_for_this_scanner_by_name_apply_too(http_server):
    pages = {
        ROBOTS: Page(
            "User-agent: WebSec-Scanner\nDisallow: /a\n\nUser-agent: *\nDisallow:\n", content_type="text/plain"
        ),
        "/": Page(html("/a", "/b")),
        "/a": Page(html()),
        "/b": Page(html()),
    }
    result, hits, _ = run(http_server, pages)
    assert hits == [ROBOTS, "/b"]
    assert result.skipped["robots-disallowed"] == 1


def test_ignoring_robots_txt_is_explicit_and_does_not_even_fetch_it(http_server):
    pages = {
        ROBOTS: Page("User-agent: *\nDisallow: /\n", content_type="text/plain"),
        "/": Page(html("/a")),
        "/a": Page(html()),
    }
    result, hits, _ = run(http_server, pages, respect_robots=False)
    assert hits == ["/a"]
    assert result.stopped_reason == "complete"


def test_missing_robots_txt_means_everything_is_allowed(http_server):
    result, hits, _ = run(http_server, {"/": Page(html("/a")), "/a": Page(html())})  # no robots.txt: 404
    assert hits == [ROBOTS, "/a"]
    assert paths(result) == ["/a"]


def test_a_robots_txt_error_page_is_not_read_as_rules(http_server):
    """A 404 whose body happens to look like rules is still "no robots.txt": nothing is disallowed."""
    pages = {
        ROBOTS: Page("User-agent: *\nDisallow: /\n", status=404, content_type="text/html"),
        "/": Page(html("/a")),
        "/a": Page(html()),
    }
    result, hits, _ = run(http_server, pages)
    assert hits == [ROBOTS, "/a"]
    assert result.skipped == {}


def test_robots_txt_that_cannot_be_read_stops_the_crawl_without_guessing(http_server):
    pages = {ROBOTS: Page("boom", status=503, content_type="text/plain"), "/": Page(html("/a")), "/a": Page(html())}
    result, hits, _ = run(http_server, pages)
    assert hits == [ROBOTS]
    assert result.pages == []
    assert result.stopped_reason == "robots-unavailable"
    assert any("robots.txt" in error for error in result.errors)


def test_only_html_pages_are_read_for_links_but_others_still_count(http_server):
    pages = {
        "/": Page(html("/doc.pdf", "/notes.txt", "/page")),
        "/doc.pdf": Page(html("/from-pdf"), content_type="application/pdf"),
        "/notes.txt": Page('<a href="/from-text">', content_type="text/plain"),
        "/page": Page(html(), content_type="application/xhtml+xml"),
        "/from-pdf": Page(html()),
        "/from-text": Page(html()),
    }
    result, hits, _ = run(http_server, pages, max_depth=3)
    assert hits == [ROBOTS, "/doc.pdf", "/notes.txt", "/page"]
    by_path = {path: page for path, page in zip(paths(result), result.pages, strict=True)}
    assert [by_path[p].checkable for p in ("/doc.pdf", "/notes.txt", "/page")] == [False, False, True]


def test_error_pages_are_recorded_but_their_links_are_not_followed(http_server):
    pages = {
        "/": Page(html("/missing", "/broken")),
        "/broken": Page(html("/hidden"), status=500),
        "/hidden": Page(html()),
    }
    result, hits, _ = run(http_server, pages, max_depth=3)
    assert hits == [ROBOTS, "/missing", "/broken"]
    assert {page.status for page in result.pages} == {404, 500}
    assert not any(page.checkable for page in result.pages)


def test_unsupported_and_credentialed_links_are_counted_not_requested(http_server):
    links = ["mailto:a@site.test", "javascript:void(0)", "tel:+1", "http://user:pw@127.0.0.1/x", "/ok"]
    result, hits, _ = run(http_server, {"/": Page(html(*links)), "/ok": Page(html())})
    assert hits == [ROBOTS, "/ok"]
    assert result.skipped["not-followable"] == 4


def test_many_query_variants_of_one_path_are_cut(http_server):
    links = [f"/list?page={n}" for n in range(1, 10)]
    pages = {"/": Page(html(*links)), "/list": Page(html())}
    result, hits, _ = run(http_server, pages, max_pages=50)
    assert hits == [ROBOTS, *links[: crawl_module.MAX_QUERY_VARIANTS]]
    assert result.skipped["query-variants"] == 9 - crawl_module.MAX_QUERY_VARIANTS


def test_the_same_path_without_a_query_is_a_variant_of_its_own(http_server):
    links = ["/list", *[f"/list?page={n}" for n in range(1, 8)]]
    result, hits, _ = run(http_server, {"/": Page(html(*links)), "/list": Page(html())})
    assert len(hits) - 1 == crawl_module.MAX_QUERY_VARIANTS  # minus robots.txt
    assert hits[1] == "/list"


def test_a_page_larger_than_the_read_limit_is_read_only_up_to_it(http_server):
    filler = "<p>x</p>" * 70000  # about 560 KB
    pages = {
        "/": Page(html("/big")),
        "/big": Page(html("/early") + filler + html("/late")),
        "/early": Page(html()),
        "/late": Page(html()),
    }
    result, hits, _ = run(http_server, pages, max_depth=3)
    assert "/early" in hits
    assert "/late" not in hits  # beyond the 512 KiB the crawler reads
    assert len(filler) > crawl_module.MAX_PAGE_BYTES


def test_cookies_and_headers_of_each_page_are_kept_for_the_checks(http_server):
    pages = {
        "/": Page(html("/a")),
        "/a": Page(html(), headers={"X-Test": "yes"}, cookies=["one=1; Path=/", "two=2; Path=/; Secure"]),
    }
    result, _, _ = run(http_server, pages)
    page = result.pages[0]
    assert page.headers["X-Test"] == "yes"
    assert page.set_cookies == ["one=1; Path=/", "two=2; Path=/; Secure"]  # two cookies, not folded into one
    assert page.checkable


def test_a_page_that_fails_to_load_is_reported_and_the_crawl_goes_on(http_server):
    base_handler = site_handler({"/": Page(html("/reset", "/ok")), "/ok": Page(html())})

    class Flaky(base_handler):
        def do_GET(self):
            if self.path == "/reset":
                type(self).hits.append(self.path)
                self.connection.shutdown(socket.SHUT_RDWR)  # hang up without answering
                return
            super().do_GET()

    result, hits, _ = run(http_server, None, handler=Flaky)
    assert paths(result) == ["/ok"]
    assert result.skipped["fetch-failed"] == 1
    assert any("/reset" in error for error in result.errors)
    assert result.stopped_reason == "complete"


def test_a_scan_limit_ends_the_crawl_and_keeps_what_was_collected(http_server):
    pages = {"/": Page(html("/a", "/b", "/c")), **{p: Page(html()) for p in ("/a", "/b", "/c")}}
    limiter = ScanLimiter(max_requests=3)  # home page, robots.txt and one more
    session = build_session(scope_host="127.0.0.1", limiter=limiter)
    result, hits, _ = run(http_server, pages, session=session)
    assert paths(result) == ["/a"]
    assert result.stopped_reason == "scan-limit"
    assert "max-requests" in result.limit_message
    assert hits == [ROBOTS, "/a"]


def test_every_request_is_a_get_and_names_the_scanner(http_server):
    handler = site_handler({"/": Page(html("/a")), "/a": Page(html())})
    run(http_server, None, handler=handler)
    assert set(handler.methods) == {"GET"}
    assert all("WebSec-Scanner" in agent for agent in handler.agents)


def test_the_same_site_gives_the_same_pages_in_the_same_order(http_server):
    pages = {"/": Page(html("/c", "/a", "/b")), **{p: Page(html("/z")) for p in ("/a", "/b", "/c", "/z")}}
    first, _, _ = run(http_server, pages, max_depth=3)
    second, _, _ = run(http_server, pages, max_depth=3)
    assert paths(first) == paths(second) == ["/c", "/a", "/b", "/z"]  # page order, not alphabetical


def test_the_discovered_set_is_bounded(http_server, monkeypatch):
    monkeypatch.setattr(crawl_module, "MAX_DISCOVERED", 4)
    links = [f"/p{n}" for n in range(10)]
    result, hits, _ = run(http_server, {"/": Page(html(*links))}, max_pages=100)
    assert len(hits) - 1 == 4
    assert result.skipped["queue-full"] == 6


def test_the_start_page_in_a_subdirectory_resolves_its_links_from_there(http_server):
    pages = {"/docs/": Page(html("a.html", "../top.html")), "/docs/a.html": Page(html()), "/top.html": Page(html())}
    handler = site_handler(pages)
    base = http_server(handler)
    session = build_session(scope_host="127.0.0.1")
    start = session.get(base + "docs/")
    result = crawl(session, start.url, start.text, CrawlOptions())
    assert paths(result) == ["/docs/a.html", "/top.html"]


def test_the_result_as_a_dict_has_counts_and_no_urls(http_server):
    pages = {"/": Page(html("/a", "mailto:x@y.test")), "/a": Page(html("/deep")), "/deep": Page(html())}
    result, _, _ = run(http_server, pages, max_depth=1)
    data = result.to_dict()
    assert data == {
        "max_depth": 1,
        "max_pages": 50,
        "max_duration": 60.0,
        "respect_robots": True,
        "pages_visited": 2,
        "skipped": {"beyond-depth": 1, "not-followable": 1},
        "stopped_reason": "max-depth",
    }


def test_options_are_validated():
    for bad in ({"max_depth": -1}, {"max_pages": 0}, {"max_duration": 0}, {"max_duration": -5}):
        with pytest.raises(ValueError):
            CrawlOptions(**bad)
    assert CrawlOptions().max_depth == 2 and CrawlOptions().max_pages == 50 and CrawlOptions().max_duration == 60.0
