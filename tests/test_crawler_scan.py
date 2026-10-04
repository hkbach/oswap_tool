"""FR-CRAWL-01/03: run_scan() with a crawl: page checks, one finding per issue, nothing else changes.

Scans a local multi-page site with run_scan() and compares with the same scan without a crawl.
"""

from __future__ import annotations

from crawl_site import Page, html, site_handler

from websec_scanner import cli, output
from websec_scanner.crawler.crawl import CrawlOptions
from websec_scanner.models import MAX_AFFECTED_URLS

XFO = {"X-Frame-Options": "DENY"}


def site():
    """Home page has X-Frame-Options; /a and /b do not. /a and /b set a cookie with no flags."""
    return {
        "/": Page(html("/a", "/b", "/doc.pdf", "/missing"), headers=XFO),
        "/a": Page(html(), cookies=["sid=aaa; Path=/"]),
        "/b": Page(html(), cookies=["sid=bbb; Path=/"]),
        "/doc.pdf": Page("%PDF", content_type="application/pdf"),
    }


def scan(http_server, pages=None, *, crawl=True, handler=None, **kwargs):
    handler = handler or site_handler(pages if pages is not None else site())
    base = http_server(handler)
    options = CrawlOptions() if crawl is True else (crawl or None)
    result = cli.run_scan(base, crawl=options, tls_probe=False, **kwargs)
    return result, handler, base


def by_id(result, finding_id):
    return [f for f in result.findings if f.id == finding_id]


def test_without_a_crawl_only_the_home_page_is_visited_and_nothing_is_added(http_server):
    result, handler, base = scan(http_server, crawl=False)
    assert "/a" not in handler.hits and "/b" not in handler.hits
    assert result.crawl is None
    finding = by_id(result, "HDR-CONTENT-SECURITY-POLICY-MISSING")[0]
    assert finding.to_dict()["affected_urls"] == [finding.url]
    assert finding.to_dict()["affected_count"] == 1


def test_the_same_issue_on_several_pages_is_one_finding_that_lists_the_pages(http_server):
    result, _, base = scan(http_server)
    csp = by_id(result, "HDR-CONTENT-SECURITY-POLICY-MISSING")
    assert len(csp) == 1  # one finding, not one per page
    data = csp[0].to_dict()
    assert data["url"] == base  # the home page was checked first, so it is the finding's own URL
    assert data["affected_urls"] == [base, base + "a", base + "b"]
    assert data["affected_count"] == 3


def test_an_issue_that_only_some_pages_have_names_only_those(http_server):
    result, _, base = scan(http_server)
    xfo = by_id(result, "HDR-X-FRAME-OPTIONS-MISSING")
    assert len(xfo) == 1
    data = xfo[0].to_dict()
    assert data["affected_urls"] == [base + "a", base + "b"]  # the home page sends the header
    assert data["url"] == base + "a"
    assert data["affected_count"] == 2


def test_cookie_findings_are_merged_too(http_server):
    result, _, base = scan(http_server)
    cookies = [f for f in result.findings if f.id.startswith("COOKIE")]
    assert cookies, "the site sets cookies without flags"
    for finding in cookies:
        data = finding.to_dict()
        assert data["affected_urls"] == [base + "a", base + "b"]
        assert data["affected_count"] == 2


def test_two_cookies_of_one_name_on_one_page_count_that_page_once(http_server):
    pages = {"/": Page(html("/a")), "/a": Page(html(), cookies=["sid=1; Path=/", "sid=2; Path=/"])}
    result, _, base = scan(http_server, pages)
    cookies = [f for f in result.findings if f.id.startswith("COOKIE")]
    assert cookies
    for finding in cookies:
        data = finding.to_dict()
        assert data["affected_urls"] == [base + "a"] and data["affected_count"] == 1


def test_different_cookies_are_different_findings_even_with_the_same_issue(http_server):
    pages = {
        "/": Page(html("/a", "/b")),
        "/a": Page(html(), cookies=["one=1; Path=/"]),
        "/b": Page(html(), cookies=["two=2; Path=/"]),
    }
    result, _, base = scan(http_server, pages)
    flags = [f for f in result.findings if f.id == "COOKIE-FLAGS-MISSING"]
    assert sorted((f.instance_key, f.to_dict()["affected_urls"][0]) for f in flags) == [
        ("one", base + "a"),
        ("two", base + "b"),
    ]
    assert all(f.to_dict()["affected_count"] == 1 for f in flags)


def test_only_successful_html_pages_are_judged(http_server):
    """A PDF and a 404 page have no security headers to speak of; they must not add URLs or findings."""
    result, handler, base = scan(http_server)
    assert "/doc.pdf" in handler.hits and "/missing" in handler.hits  # they were requested...
    for finding in result.findings:
        assert not any(url.endswith(("/doc.pdf", "/missing")) for url in finding.to_dict()["affected_urls"])


def test_fingerprints_do_not_change_when_a_crawl_is_added(http_server):
    """--baseline and --suppressions keep working: a finding has the same identity with or without a crawl."""
    base = http_server(site_handler(site()))  # one server: a fingerprint includes the origin
    plain = cli.run_scan(base, tls_probe=False)
    crawled = cli.run_scan(base, crawl=CrawlOptions(), tls_probe=False)
    plain_prints = {f.fingerprint for f in plain.findings}
    assert plain_prints and plain_prints <= {f.fingerprint for f in crawled.findings}


def test_the_summary_counts_a_merged_finding_once(http_server):
    result, _, _ = scan(http_server)
    report = output.build_report(result)
    assert sum(report["summary"].values()) == len(report["findings"])
    csp = [f for f in report["findings"] if f["id"] == "HDR-CONTENT-SECURITY-POLICY-MISSING"]
    assert len(csp) == 1


def test_the_crawl_object_in_the_report(http_server):
    result, _, _ = scan(http_server)
    report = output.build_report(result)
    assert report["crawl"] == {
        "max_depth": 2,
        "max_pages": 50,
        "max_duration": 60.0,
        "respect_robots": True,
        "pages_visited": 5,
        "skipped": {},
        "stopped_reason": "complete",
    }
    plain, _, _ = scan(http_server, crawl=False)
    assert output.build_report(plain)["crawl"] is None


def test_the_crawl_runs_after_the_other_checks(http_server):
    """A scan cut short by --max-requests must lose crawled pages before it loses its normal checks."""
    _, handler, _ = scan(http_server)
    assert handler.hits.index("/a") > handler.hits.index("/.git/HEAD")  # a path of the exposed-files check


def test_a_request_cap_during_the_crawl_keeps_the_pages_read_so_far(http_server):
    plain, plain_handler, _ = scan(http_server, crawl=False)
    cap = len(plain_handler.hits) + 2  # the normal checks, then robots.txt and one page
    result, handler, base = scan(http_server, max_requests=cap)
    assert result.limits["stopped_by"] == "max-requests"
    assert any(error.startswith("Scan stopped early") for error in result.errors)
    assert result.crawl.stopped_reason == "scan-limit"
    xfo = by_id(result, "HDR-X-FRAME-OPTIONS-MISSING")
    assert xfo and xfo[0].to_dict()["affected_urls"] == [base + "a"]  # /a was read before the cap, /b was not


def test_a_robots_txt_that_cannot_be_read_is_reported_and_the_rest_of_the_scan_is_unaffected(http_server):
    pages = {**site(), "/robots.txt": Page("down", status=503, content_type="text/plain")}
    result, _, _ = scan(http_server, pages)
    assert result.crawl.stopped_reason == "robots-unavailable"
    assert any("robots.txt" in error and "--ignore-robots" in error for error in result.errors)
    assert result.baseline_fetched and result.limits.get("stopped_by") is None
    assert by_id(result, "HDR-CONTENT-SECURITY-POLICY-MISSING")[0].to_dict()["affected_count"] == 1


def test_a_crawl_with_no_page_check_selected_is_not_run(http_server):
    result, handler, _ = scan(http_server, groups=["exposed-files"])
    assert "/a" not in handler.hits
    assert result.crawl is None
    assert any("--crawl" in error and "ignored" in error for error in result.errors)


def test_page_checks_follow_the_selected_groups(http_server):
    only_cookies, _, _ = scan(http_server, groups=["cookies"])
    assert not [f for f in only_cookies.findings if f.id.startswith("HDR")]
    assert [f for f in only_cookies.findings if f.id.startswith("COOKIE")]
    only_headers, _, _ = scan(http_server, groups=["headers"])
    assert not [f for f in only_headers.findings if f.id.startswith("COOKIE")]
    assert by_id(only_headers, "HDR-X-FRAME-OPTIONS-MISSING")[0].to_dict()["affected_count"] == 2


def test_the_checks_run_once_per_page_not_once_per_link(http_server):
    """Ten links to one page, and a page linked from both others, still count the page once."""
    pages = {
        "/": Page(html(*["/a"] * 10, "/b")),
        "/a": Page(html("/b", "/a")),
        "/b": Page(html("/a")),
    }
    result, handler, base = scan(http_server, pages)
    assert handler.hits.count("/a") == 1 and handler.hits.count("/b") == 1
    assert by_id(result, "HDR-CONTENT-SECURITY-POLICY-MISSING")[0].to_dict()["affected_urls"] == [
        base,
        base + "a",
        base + "b",
    ]


def test_the_url_list_of_one_finding_is_capped_but_the_count_is_not(http_server):
    total = MAX_AFFECTED_URLS + 6
    pages = {"/": Page(html(*[f"/p{n}" for n in range(total)])), **{f"/p{n}": Page(html()) for n in range(total)}}
    handler = site_handler(pages)
    base = http_server(handler)
    result = cli.run_scan(base, crawl=CrawlOptions(max_pages=100), tls_probe=False)
    data = by_id(result, "HDR-CONTENT-SECURITY-POLICY-MISSING")[0].to_dict()
    assert len(data["affected_urls"]) == MAX_AFFECTED_URLS
    assert data["affected_count"] == total + 1  # every page, the home page included


def test_secrets_in_a_crawled_url_are_redacted_unless_the_operator_asks(http_server):
    pages = {"/": Page(html("/a?token=SECRETVALUE123")), "/a": Page(html())}
    result, _, _ = scan(http_server, pages)
    safe = output.build_report(result)
    assert "SECRETVALUE123" not in str(safe)
    csp = next(f for f in safe["findings"] if f["id"] == "HDR-CONTENT-SECURITY-POLICY-MISSING")
    assert any("token=<redacted len=" in url for url in csp["affected_urls"])
    shown = output.build_report(result, show_secrets=True)
    assert "SECRETVALUE123" in str(shown)


def test_credentials_given_to_the_scan_are_masked_in_the_crawl_urls_too(http_server):
    pages = {"/": Page(html("/a?page=OPERATORSECRET9")), "/a": Page(html())}
    result, _, _ = scan(http_server, pages)
    report = output.build_report(result, secrets=["OPERATORSECRET9"], show_secrets=True)
    assert "OPERATORSECRET9" not in str(report)


def test_crawl_is_off_unless_asked_for(http_server):
    result = cli.run_scan(http_server(site_handler(site())), tls_probe=False)
    assert result.crawl is None
