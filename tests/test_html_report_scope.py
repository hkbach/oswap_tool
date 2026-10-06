"""FR-REPORT-09: the HTML report shows what the scan did and what it read, not only its findings.

Scan details (versions, scan id, requests sent, limits, stopped early), and the API inventory read
from --api-spec. Everything that came from a spec file or a scanned site is untrusted text.
"""

from __future__ import annotations

import json
import re

from mock_server import Handler as MockHandler
from test_html_report import _report

from websec_scanner import __version__, cli, rule_loader
from websec_scanner.html_report import render_html

LIMITS_NONE = {
    "rate_limit": None,
    "max_requests": None,
    "max_duration": None,
    "requests_sent": 14,
    "slowdowns": 0,
    "stopped_by": None,
}


def with_details(api=None, **limits):
    return _report(
        api=api,
        scanner_version="9.8.7",
        rules_version="3.2.1",
        scan_id="11111111-2222-3333-4444-555555555555",
        limits={**LIMITS_NONE, **limits},
    )


def api(endpoints=None, **overrides):
    data = {
        "source": "petstore.yaml",
        "format": "openapi",
        "version": "3.0.3",
        "title": "Pet Store",
        "servers": ["https://api.example.test/v1", "https://staging.example.test/v1"],
        "security_schemes": [
            {"name": "bearer", "type": "http", "detail": "bearer"},
            {"name": "legacy", "type": "apiKey", "detail": ""},
        ],
        "endpoint_count": 0,
        "endpoints": [],
    }
    data["endpoints"] = (
        endpoints
        if endpoints is not None
        else [
            {
                "method": "GET",
                "path": "/pets/{id}",
                "operation_id": "getPet",
                "parameters": [
                    {"name": "id", "in": "path", "required": True},
                    {"name": "expand", "in": "query", "required": False},
                ],
                "security": ["bearer"],
                "deprecated": False,
            },
            {
                "method": "DELETE",
                "path": "/pets/{id}",
                "operation_id": "",
                "parameters": [],
                "security": [],
                "deprecated": True,
            },
        ]
    )
    data["endpoint_count"] = len(data["endpoints"])
    data.update(overrides)
    return data


def endpoint(n):
    return {
        "method": "GET",
        "path": f"/item/{n}",
        "operation_id": "",
        "parameters": [],
        "security": [],
        "deprecated": False,
    }


def cells(html: str, label: str) -> str:
    """The value cell of the scan-details row called ``label`` (the row is ``<th>label</th><td>value</td>``)."""
    match = re.search(rf"<th>{re.escape(label)}</th><td>(.*?)</td>", html, re.S)
    assert match, f"no row {label!r}"
    return match.group(1)


# --- scan details ---------------------------------------------------------------------------------


def test_a_report_without_the_new_fields_still_renders_without_the_new_rows():
    """A minimal report (the older tests' shape) has no limits, versions or api: nothing is invented."""
    html = render_html(_report())
    for label in ("Scanner version", "Rules version", "Scan ID", "Requests sent", "Limits", "Stopped early by"):
        assert f"<th>{label}</th>" not in html
    assert "API inventory" not in html


def test_versions_and_scan_id_are_shown():
    html = render_html(with_details())
    assert cells(html, "Scanner version") == "9.8.7"
    assert cells(html, "Rules version") == "3.2.1"
    assert cells(html, "Scan ID") == "11111111-2222-3333-4444-555555555555"


def test_requests_sent_is_shown():
    assert cells(render_html(with_details(requests_sent=1234)), "Requests sent") == "1234"
    assert cells(render_html(with_details(requests_sent=0)), "Requests sent") == "0"


def test_no_limits_set_says_so():
    assert cells(render_html(with_details()), "Limits") == "none set"


def test_each_limit_that_was_set_is_named_and_the_others_are_not():
    html = render_html(with_details(rate_limit=2.5, max_requests=100, max_duration=60))
    assert cells(html, "Limits") == "rate limit 2.5 requests/s, max 100 requests, max 60 s"
    only = render_html(with_details(max_requests=50))
    assert cells(only, "Limits") == "max 50 requests"


def test_a_whole_number_rate_has_no_trailing_zero():
    assert cells(render_html(with_details(rate_limit=5.0)), "Limits") == "rate limit 5 requests/s"


def test_stopped_early_names_the_option_that_did_it():
    html = render_html(with_details(stopped_by="max-requests"))
    assert cells(html, "Stopped early by") == "--max-requests"
    assert cells(render_html(with_details(stopped_by="max-duration")), "Stopped early by") == "--max-duration"
    assert "Stopped early by" not in render_html(with_details(stopped_by=None))


def test_slowdowns_are_shown_only_when_there_were_some():
    html = render_html(with_details(slowdowns=3))
    assert cells(html, "Backed off") == "3 time(s) after HTTP 429 or 503 answers"
    assert "Backed off" not in render_html(with_details(slowdowns=0))


def test_scan_details_are_escaped():
    report = with_details()
    report["scan_id"] = "<img src=x onerror=alert(1)>"
    report["scanner_version"] = '"><script>x</script>'
    html = render_html(report)
    assert "<img" not in html and "<script>" not in html
    assert "&lt;img src=x" in html


def test_a_real_scan_report_shows_its_own_numbers(http_server, tmp_path):
    out = tmp_path / "r.json"
    html_out = tmp_path / "r.html"
    cli.main([http_server(MockHandler), "--yes", "--no-color", "--json", str(out), "--html", str(html_out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    html = html_out.read_text(encoding="utf-8")
    assert cells(html, "Scanner version") == __version__
    assert cells(html, "Rules version") == rule_loader.rules_version()
    assert cells(html, "Scan ID") == report["scan_id"]
    assert cells(html, "Requests sent") == str(report["limits"]["requests_sent"])
    assert report["limits"]["requests_sent"] > 5


# --- API inventory ---------------------------------------------------------------------------------


def test_no_api_means_no_api_card():
    assert "API inventory" not in render_html(with_details(api=None))


def test_the_api_card_shows_what_the_spec_declares():
    html = render_html(with_details(api=api()))
    assert "<h2>API inventory</h2>" in html
    assert "Pet Store" in html and "openapi 3.0.3" in html and "petstore.yaml" in html
    assert "https://api.example.test/v1" in html and "https://staging.example.test/v1" in html
    assert "bearer (http, bearer)" in html and "legacy (apiKey)" in html
    assert "/pets/{id}" in html
    assert "id (path)" in html and "expand (query)" in html
    assert "deprecated" in html


def test_the_api_card_says_nothing_was_requested():
    html = render_html(with_details(api=api()))
    assert "Read from the spec file only: no request was sent to any endpoint or server it names." in html


def test_each_endpoint_is_one_row_with_its_method_and_auth():
    html = render_html(with_details(api=api()))
    rows = re.findall(r'<tr class="endpoint">(.*?)</tr>', html, re.S)
    assert len(rows) == 2
    assert "GET" in rows[0] and "bearer" in rows[0] and "id (path)" in rows[0]
    assert "DELETE" in rows[1] and "deprecated" in rows[1]
    assert "<td>-</td>" in rows[1] and "<td>-</td>" not in rows[0]  # no parameters for DELETE
    assert "deprecated" not in rows[0]  # only the deprecated endpoint is flagged
    assert "none declared" in rows[1] and "none declared" not in rows[0]  # no security scheme for DELETE


def test_an_api_without_endpoints_says_so_and_has_no_table():
    html = render_html(with_details(api=api(endpoints=[], servers=[], security_schemes=[])))
    assert "No endpoints declared." in html
    assert "Servers:" not in html and "Security schemes:" not in html  # nothing to list
    assert 'class="endpoint"' not in html


def test_only_the_first_hundred_endpoints_are_listed_and_the_rest_counted():
    html = render_html(with_details(api=api(endpoints=[endpoint(n) for n in range(150)])))
    assert html.count('<tr class="endpoint">') == 100
    assert "/item/99" in html and "/item/100" not in html
    assert "and 50 more endpoint(s); all of them are in the JSON report" in html
    one_over = render_html(with_details(api=api(endpoints=[endpoint(n) for n in range(101)])))
    assert "and 1 more endpoint(s); all of them are in the JSON report" in one_over  # even one is not hidden
    exact = render_html(with_details(api=api(endpoints=[endpoint(n) for n in range(100)])))
    assert "more endpoint(s)" not in exact


def test_text_from_a_spec_is_escaped_and_control_characters_are_made_visible():
    hostile = "<script>alert(1)</script>"
    spec = api(
        endpoints=[
            {
                "method": "GET",
                "path": '/x"><img src=x onerror=alert(1)>\x1b[2J',
                "operation_id": "",
                "parameters": [{"name": hostile, "in": "query", "required": False}],
                "security": [hostile],
                "deprecated": False,
            }
        ],
        title=hostile,
        source=hostile,
        version=hostile,
        servers=[hostile],
        security_schemes=[{"name": hostile, "type": "apiKey", "detail": hostile}],
    )
    html = render_html(with_details(api=spec))
    assert "<script>" not in html and "<img" not in html and "\x1b" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "\\x1b[2J" in html  # shown, not acted on


def test_the_report_with_an_api_card_is_still_standalone():
    html = render_html(with_details(api=api()))
    assert "<script" not in html and "<link" not in html and "<img" not in html
    assert " src=" not in html and not re.search(r'href="https?:', html.replace('href="#', ""))


def test_the_new_text_makes_no_absolute_claims():
    html = render_html(with_details(api=api(), stopped_by="max-requests", slowdowns=2, rate_limit=1))
    text = re.sub(r"<style>.*?</style>", "", html, flags=re.S)  # the style sheet has "width: 100%"
    assert not re.search(r"guarantee|100%|completely safe|fully secure", text, re.I)


def test_an_api_spec_given_on_the_command_line_reaches_the_html(http_server, tmp_path):
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "info": {"title": "Orders", "version": "1"},
                "paths": {"/orders": {"get": {"responses": {"200": {"description": "ok"}}}}},
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "r.html"
    cli.main([http_server(MockHandler), "--yes", "--no-color", "--api-spec", str(spec), "--html", str(out)])
    html = out.read_text(encoding="utf-8")
    assert "<h2>API inventory</h2>" in html and "Orders" in html and "/orders" in html
    assert str(tmp_path) not in html  # the spec's file name, never its location


# --- the crawl card (FR-CRAWL-01) ------------------------------------------------------------------------


def crawl(**overrides):
    data = {
        "max_depth": 2,
        "max_pages": 50,
        "max_duration": 60.0,
        "respect_robots": True,
        "pages_visited": 3,
        "skipped": {},
        "stopped_reason": "complete",
    }
    data.update(overrides)
    return data


def test_no_crawl_means_no_crawl_card():
    assert "<h2>Crawl</h2>" not in render_html(_report(crawl=None))
    assert "<h2>Crawl</h2>" not in render_html(_report())


def test_the_crawl_card_says_what_was_covered_and_why_it_stopped():
    html = render_html(_report(crawl=crawl(stopped_reason="max-pages", pages_visited=50)))
    assert "<h2>Crawl</h2>" in html
    assert "50 page(s) visited: stopped at --crawl-max-pages." in html
    assert "Limits: depth 2, 50 pages, 60 s; robots.txt followed." in html
    assert "Links not followed" not in html  # nothing was left alone


def test_the_crawl_card_lists_the_links_it_left_alone():
    html = render_html(_report(crawl=crawl(skipped={"other-origin": 4, "robots-disallowed": 1})))
    assert "Links not followed:" in html
    assert "<li>4 &times; other origin</li>" in html
    assert "<li>1 &times; disallowed by robots.txt</li>" in html


def test_the_crawl_card_says_when_robots_txt_was_ignored():
    html = render_html(_report(crawl=crawl(respect_robots=False)))
    assert "robots.txt ignored (--ignore-robots)." in html
    assert "robots.txt followed" not in html
