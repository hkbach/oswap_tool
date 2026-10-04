"""FR-REPORT-10: the report lists the pages the scan fetched, with what was done to each.

``pages`` is a top-level key of the JSON report (schema 1.11): the target page first, then the pages a
crawl visited, in the order they were visited. It exists without a crawl too (one entry), and is empty
when the target could not be fetched.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import requests
from crawl_site import Page, html, site_handler

from websec_scanner import cli, models, output, web
from websec_scanner.crawler.crawl import CrawlOptions

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "report.schema.json"
PAGE_CHECKS = ("security-headers", "cookies")


def site():
    """Home has X-Frame-Options; /a and /b do not; /a and /b set a cookie with no flags."""
    return {
        "/": Page(html("/a", "/b", "/doc.pdf", "/gone", "/moved"), headers={"X-Frame-Options": "DENY"}),
        "/a": Page(html(), cookies=["sid=aaa; Path=/"]),
        "/b": Page(html(), cookies=["sid=bbb; Path=/"]),
        "/doc.pdf": Page("%PDF", content_type="application/pdf"),
        "/moved": Page(status=302, headers={"Location": "/a"}),
    }


def scan(http_server, pages=None, *, crawl=True, **kwargs):
    handler = site_handler(pages if pages is not None else site())
    base = http_server(handler)
    options = (CrawlOptions() if crawl is True else crawl) or None
    result = cli.run_scan(base, crawl=options, tls_probe=False, **kwargs)
    return result, base


def findings_on(report, url):
    """Independent of the counter under test: distinct findings (by fingerprint) of the page checks on this URL."""
    return len(
        {f["fingerprint"] for f in report["findings"] if f["check"] in PAGE_CHECKS and url in f["affected_urls"]}
    )


# --- what is listed ------------------------------------------------------------------------------------------


def test_without_a_crawl_only_the_target_page_is_listed(http_server):
    result, base = scan(http_server, crawl=False)
    report = output.build_report(result)
    assert len(report["pages"]) == 1
    page = report["pages"][0]
    assert page["url"] == base and page["status"] == 200 and page["depth"] == 0 and page["checked"] is True
    assert page["findings"] == findings_on(report, base) > 0


def test_a_crawl_lists_the_target_first_then_each_page_in_visiting_order(http_server):
    result, base = scan(http_server)
    report = output.build_report(result)
    assert [(p["url"], p["depth"]) for p in report["pages"]] == [
        (base, 0),
        (base + "a", 1),
        (base + "b", 1),
        (base + "doc.pdf", 1),
        (base + "gone", 1),
        (base + "moved", 1),
    ]
    assert [p["status"] for p in report["pages"]] == [200, 200, 200, 200, 404, 302]


def test_only_successful_html_pages_are_marked_checked(http_server):
    result, base = scan(http_server)
    checked = {p["url"][len(base) :]: p["checked"] for p in output.build_report(result)["pages"]}
    assert checked == {"": True, "a": True, "b": True, "doc.pdf": False, "gone": False, "moved": False}


def test_the_number_of_findings_of_each_page_matches_the_findings_that_list_it(http_server):
    result, _ = scan(http_server)
    report = output.build_report(result)
    for page in report["pages"]:
        assert page["findings"] == findings_on(report, page["url"]), page["url"]
    unchecked = [p for p in report["pages"] if not p["checked"]]
    assert unchecked and all(p["findings"] == 0 for p in unchecked)
    assert report["pages"][0]["findings"] != report["pages"][1]["findings"]  # /a also lacks X-Frame-Options


def test_the_count_is_exact_beyond_the_twenty_urls_a_finding_lists(http_server):
    total = models.MAX_AFFECTED_URLS + 6
    pages = {"/": Page(html(*[f"/p{n}" for n in range(total)])), **{f"/p{n}": Page(html()) for n in range(total)}}
    result, _ = scan(http_server, pages, crawl=CrawlOptions(max_pages=100))
    report = output.build_report(result)
    counts = {p["findings"] for p in report["pages"]}
    assert len(report["pages"]) == total + 1
    assert len(counts) == 1 and counts != {0}  # every page has the same issues, all of them counted
    csp = next(f for f in report["findings"] if f["id"] == "HDR-CONTENT-SECURITY-POLICY-MISSING")
    assert len(csp["affected_urls"]) == models.MAX_AFFECTED_URLS and csp["affected_count"] == total + 1


def test_the_target_page_is_where_the_redirects_ended_not_where_the_scan_started(http_server):
    pages = {"/start": Page(status=302, headers={"Location": "/"}), "/": Page(html())}
    base = http_server(site_handler(pages))
    report = output.build_report(cli.run_scan(base + "start", tls_probe=False))
    assert [(p["url"], p["status"]) for p in report["pages"]] == [(base, 200)]


def test_the_status_of_the_target_page_is_the_one_it_answered_with(http_server):
    pages = {"/": Page(html("/a"), status=203), "/a": Page(html(), status=206)}
    result, base = scan(http_server, pages)
    assert [(p["url"], p["status"]) for p in output.build_report(result)["pages"]] == [(base, 203), (base + "a", 206)]


def test_two_cookies_of_one_name_on_the_target_page_count_each_finding_once(http_server):
    pages = {"/": Page(html(), cookies=["sid=1; Path=/", "sid=2; Path=/"])}
    result, base = scan(http_server, pages, crawl=False)
    report = output.build_report(result)
    assert report["pages"][0]["findings"] == findings_on(report, base)


def test_a_page_with_two_cookies_of_one_name_counts_each_finding_once(http_server):
    pages = {"/": Page(html("/a")), "/a": Page(html(), cookies=["sid=1; Path=/", "sid=2; Path=/"])}
    result, base = scan(http_server, pages)
    report = output.build_report(result)
    assert next(p for p in report["pages"] if p["url"] == base + "a")["findings"] == findings_on(report, base + "a")


# --- which checks ran --------------------------------------------------------------------------------------------


def test_without_the_header_and_cookie_groups_no_page_is_marked_checked(http_server):
    result, _ = scan(http_server, groups=["exposed-files"])
    report = output.build_report(result)
    assert [(p["checked"], p["findings"]) for p in report["pages"]] == [(False, 0)]


def test_the_cookies_group_alone_still_counts_as_checking_the_page(http_server):
    result, base = scan(http_server, groups=["cookies"])
    report = output.build_report(result)
    pages = {p["url"][len(base) :]: p for p in report["pages"]}
    assert pages["a"]["checked"] is True and pages["a"]["findings"] == 1  # the cookie flags
    assert pages[""]["checked"] is True  # the target page was checked too, for cookies only
    assert pages[""]["findings"] == 0  # the home page sets no cookie


# --- when the scan did not get that far ------------------------------------------------------------------------------


def test_a_target_that_could_not_be_fetched_has_no_pages():
    result = cli.run_scan("http://127.0.0.1:1/", timeout=1, tls_probe=False)
    assert output.build_report(result)["pages"] == []


def test_a_crawl_stopped_by_robots_txt_being_unreadable_lists_only_the_target(http_server):
    pages = {**site(), "/robots.txt": Page("down", status=503, content_type="text/plain")}
    result, base = scan(http_server, pages)
    assert [p["url"] for p in output.build_report(result)["pages"]] == [base]


def test_a_request_cap_during_the_crawl_keeps_the_pages_fetched_so_far(http_server):
    plain, _ = scan(http_server, crawl=False)
    cap = plain.limits["requests_sent"] + 2  # the normal checks, then robots.txt and one page
    result, base = scan(http_server, max_requests=cap)
    assert [p["url"] for p in output.build_report(result)["pages"]] == [base, base + "a"]


def test_the_list_is_cut_but_the_visit_count_still_says_how_many(http_server, monkeypatch):
    monkeypatch.setattr(models, "MAX_REPORT_PAGES", 3)
    result, _ = scan(http_server)
    report = output.build_report(result)
    assert len(report["pages"]) == 3
    assert report["crawl"]["pages_visited"] == 6  # so a reader can tell the list is shorter than the crawl


# --- secrets ----------------------------------------------------------------------------------------------------------


def test_a_token_in_a_crawled_url_is_masked_unless_the_operator_asks(http_server):
    pages = {"/": Page(html("/a?token=SECRETVALUE123")), "/a": Page(html())}
    result, _ = scan(http_server, pages)
    safe = output.build_report(result)
    assert "SECRETVALUE123" not in json.dumps(safe)
    assert any("token=<redacted len=" in p["url"] for p in safe["pages"])
    assert "SECRETVALUE123" in json.dumps(output.build_report(result, show_secrets=True)["pages"])


def test_the_operators_own_credential_is_masked_in_the_pages_even_with_show_secrets(http_server):
    pages = {"/": Page(html("/a?page=OPERATORSECRET9")), "/a": Page(html())}
    result, _ = scan(http_server, pages)
    report = output.build_report(result, show_secrets=True, secrets=["OPERATORSECRET9"])
    assert "OPERATORSECRET9" not in json.dumps(report)


# --- the schema and the other entry points ----------------------------------------


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def test_the_schema_version_is_1_11_and_the_report_validates(http_server, validator):
    assert validator.schema["properties"]["schema_version"]["const"] == models.SCHEMA_VERSION == "1.11"
    for crawl in (False, True):
        result, _ = scan(http_server, crawl=crawl)
        validator.validate(output.build_report(result))
    validator.validate(output.build_report(cli.run_scan("http://127.0.0.1:1/", timeout=1, tls_probe=False)))


def test_the_schema_rejects_a_malformed_pages_list(http_server, validator):
    result, _ = scan(http_server)
    report = json.loads(json.dumps(output.build_report(result)))
    for mutate in (
        lambda r: r.pop("pages"),
        lambda r: r["pages"][0].pop("url"),
        lambda r: r["pages"][0].update(status="200"),
        lambda r: r["pages"][0].update(depth=-1),
        lambda r: r["pages"][0].update(checked="yes"),
        lambda r: r["pages"][0].update(findings=-1),
        lambda r: r["pages"][0].update(extra=1),
        lambda r: r["pages"][0].update(status=99),
        lambda r: r["pages"][0].update(status=600),
        lambda r: r.update(pages=[r["pages"][0]] * 501),
        lambda r: r.update(pages={}),
    ):
        broken = json.loads(json.dumps(report))
        mutate(broken)
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(broken)


def test_the_cli_writes_the_pages_to_the_json_file(http_server, tmp_path):
    handler = site_handler(site())
    out = tmp_path / "r.json"
    cli.main([http_server(handler), "--yes", "--no-color", "--no-tls-probe", "--crawl", "--json", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["pages"]) == 6 and data["pages"][0]["depth"] == 0


def test_the_web_ui_returns_the_same_pages_as_the_cli(http_server):
    import threading

    base = http_server(site_handler(site()))
    server = web.build_server("127.0.0.1", 0, timeout=5, tls_probe=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ui = f"http://127.0.0.1:{server.server_address[1]}"
        data = requests.post(
            f"{ui}/api/scan", json={"target": base, "authorized": True, "crawl": True}, timeout=120
        ).json()
    finally:
        server.shutdown()
        server.server_close()
    cli_report = output.build_report(cli.run_scan(base, tls_probe=False, crawl=CrawlOptions()))
    assert data["pages"] == cli_report["pages"]


def test_findings_of_other_checks_are_not_counted_against_the_target_page(http_server):
    """An exposed file is a finding of the scan, not of the page's headers or cookies."""
    pages = {"/": Page(html()), "/.git/HEAD": Page("ref: refs/heads/main\n", content_type="text/plain")}
    result, base = scan(http_server, pages, crawl=False)
    report = output.build_report(result)
    assert any(f["check"] == "sensitive-paths" for f in report["findings"])  # the exposed file was found
    assert report["pages"][0]["findings"] == findings_on(report, base)
    only_page_checks = {f["fingerprint"] for f in report["findings"] if f["check"] in PAGE_CHECKS}
    assert report["pages"][0]["findings"] == len(only_page_checks)


def test_a_page_that_is_not_judged_is_not_judged_for_cookies_either(http_server):
    pages = {
        "/": Page(html("/gone", "/doc.pdf")),
        "/gone": Page(status=404, cookies=["ghost=1; Path=/"]),
        "/doc.pdf": Page("%PDF", content_type="application/pdf", cookies=["phantom=1; Path=/"]),
    }
    result, base = scan(http_server, pages)
    report = output.build_report(result)
    assert not any(f["instance_key"] in ("ghost", "phantom") for f in report["findings"])
    unchecked = {p["url"][len(base) :]: (p["checked"], p["findings"]) for p in report["pages"][1:]}
    assert unchecked == {"gone": (False, 0), "doc.pdf": (False, 0)}


def test_the_cut_in_the_code_is_the_cut_the_schema_allows():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["properties"]["pages"]["maxItems"] == models.MAX_REPORT_PAGES == 500


def test_only_the_checks_that_judge_a_page_count_toward_its_findings():
    def finding(check, fingerprint):
        return models.Finding(
            id="X-Y", title="t", severity=models.Severity.LOW, owasp_category="o", description="d",
            check=check, fingerprint=fingerprint,
        )  # fmt: skip

    findings = [
        finding("security-headers", "a"),
        finding("security-headers", "b"),
        finding("cookies", "c"),
        finding("cookies", "c"),  # the same cookie on a redirect hop and on the final answer: one finding
        finding("hsts-start-host", "d"),  # about the host the scan started on, not about this page
        finding("tls", "e"),
        finding("sensitive-paths", "f"),
        finding("cors", "g"),
    ]
    assert cli._count_page_findings(findings) == 3
    assert cli._count_page_findings([]) == 0
