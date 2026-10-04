"""FR-CRAWL-01: which links a page offers, and which of them the crawler may follow.

Pure functions, no network: ``extract_links`` reads the HTML, ``normalize`` decides what a
URL is (or whether it is a link to follow at all).
"""

from __future__ import annotations

import pytest

from websec_scanner.crawler import links

BASE = "http://site.test/a/b.html"


def extract(html: str, base: str = BASE) -> list[str]:
    return links.extract_links(html, base)


def test_anchor_and_area_links_are_resolved_against_the_page():
    html = '<a href="c.html">x</a><area href="/top"><a href="//other.test/x"><a href="?page=2">p</a>'
    assert extract(html) == [
        "http://site.test/a/c.html",
        "http://site.test/top",
        "http://other.test/x",
        "http://site.test/a/b.html?page=2",
    ]


def test_only_anchors_and_areas_count_as_links():
    """Images, scripts, stylesheets and forms are not pages to visit (forms are FR-CRAWL-05)."""
    html = (
        '<img src="/i.png"><script src="/s.js"></script><link rel="stylesheet" href="/c.css">'
        '<form action="/post"><input></form><iframe src="/frame"></iframe><a href="/real">x</a>'
        # an href on any other element is not a link to follow either
        '<form href="/form-href"></form><iframe href="/frame-href"></iframe><div href="/div-href"></div>'
    )
    assert extract(html) == ["http://site.test/real"]


def test_base_tag_changes_how_relative_links_resolve():
    html = '<base href="http://site.test/docs/"><a href="x.html">x</a>'
    assert extract(html) == ["http://site.test/docs/x.html"]


def test_only_the_first_base_tag_counts_and_a_bad_one_is_ignored():
    assert extract('<base href="/one/"><base href="/two/"><a href="x">x</a>') == ["http://site.test/one/x"]
    assert extract('<base href="http://[bad"><a href="x">x</a>') == ["http://site.test/a/x"]


def test_duplicates_are_listed_once_in_first_seen_order():
    assert extract('<a href="/b">1</a><a href="/a">2</a><a href="/b">3</a>') == [
        "http://site.test/b",
        "http://site.test/a",
    ]


def test_broken_html_does_not_raise():
    assert extract('<a href="/ok"><a href=><a <<<<< href="/also"') == ["http://site.test/ok"]
    assert extract("") == []
    assert extract("\x00\x00<a href='/x'>") == ["http://site.test/x"]


def test_unusable_hrefs_are_skipped_not_fatal():
    # an unparsable URL must not stop the rest of the page from being read
    assert extract('<a href="http://[bad">x</a><a href="/good">y</a>') == ["http://site.test/good"]


def test_a_huge_number_of_links_is_cut():
    html = "".join(f'<a href="/p{i}">x</a>' for i in range(links.MAX_LINKS_PER_PAGE + 50))
    found = extract(html)
    assert len(found) == links.MAX_LINKS_PER_PAGE
    assert found[0] == "http://site.test/p0"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://Site.TEST/Path", "http://site.test/Path"),  # host lower-cased, path case kept
        ("http://site.test", "http://site.test/"),  # empty path becomes /
        ("http://site.test:80/x", "http://site.test/x"),  # default port dropped
        ("https://site.test:443/x", "https://site.test/x"),
        ("http://site.test:8080/x", "http://site.test:8080/x"),  # other ports kept
        ("http://site.test/x#section", "http://site.test/x"),  # fragment dropped
        ("http://site.test/x?b=2&a=1", "http://site.test/x?b=2&a=1"),  # query kept exactly
        ("http://site.test/x?", "http://site.test/x"),  # empty query dropped
        ("http://[::1]:8000/x", "http://[::1]:8000/x"),
    ],
)
def test_normalize_gives_one_spelling_per_url(url, expected):
    assert links.normalize(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "mailto:someone@site.test",
        "javascript:void(0)",
        "tel:+000000",
        "data:text/html,<p>x</p>",
        "ftp://site.test/file",
        "file:///etc/hosts",
        "http://user:pass@site.test/x",  # a URL that carries credentials is never followed
        "http://user@site.test/x",
        "http:///x",  # no host
        "http://site.test:99999/x",  # impossible port
        "x" * 3000,
        "http://site.test/" + "a" * links.MAX_URL_LENGTH,
    ],
)
def test_normalize_refuses_what_is_not_a_followable_page(url):
    assert links.normalize(url) is None


def test_same_origin_compares_scheme_host_and_port():
    origin = links.origin_of("http://site.test/a")
    assert links.origin_of("http://site.test:80/b") == origin
    assert links.origin_of("http://SITE.test/c") == origin
    assert links.origin_of("https://site.test/a") != origin
    assert links.origin_of("http://site.test:8080/a") != origin
    assert links.origin_of("http://other.test/a") != origin
    assert links.origin_of("http://sub.site.test/a") != origin
