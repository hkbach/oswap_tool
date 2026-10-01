"""FR-MODEL-03: CVSS v3.1 base score formula, checked against officially published examples."""

from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest
from mock_server import Handler as MockHandler

from websec_scanner import catalog, cli, cvss, output, web
from websec_scanner.html_report import render_html
from websec_scanner.report import print_report


@pytest.mark.parametrize(
    "vector, expected",
    [
        # Worst case on every metric (e.g. CVE-2021-44228 "Log4Shell" uses this exact vector).
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # Unauthenticated remote denial of service, no confidentiality/integrity impact.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        # Local, low-privilege full compromise (typical local-privilege-escalation vector).
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        # Scope-changed, reflected-XSS-style vector from the CVSS v3.1 specification examples.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        # No impact at all: base score is 0, not negative or undefined.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score_matches_published_examples(vector, expected):
    assert cvss.base_score(vector) == expected


def test_score_is_never_above_ten():
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H") <= 10.0


@pytest.mark.parametrize(
    "bad_vector",
    [
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # missing "CVSS:3.1/" prefix
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # invalid AV value
        "",
    ],
)
def test_invalid_vectors_are_rejected(bad_vector):
    with pytest.raises(ValueError):
        cvss.base_score(bad_vector)


def test_parse_vector_returns_each_metric():
    metrics = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert metrics == {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}


@pytest.fixture
def scanned_report(http_server):
    """One real scan of the mock server, as every output format receives it."""
    return output.build_report(cli.run_scan(http_server(MockHandler)))


def test_console_report_shows_the_score_as_estimated(scanned_report):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        print_report(scanned_report, use_color=False)
    printed = buffer.getvalue()
    scored = [f for f in scanned_report["findings"] if f["cvss_vector"]]
    assert scored, "the mock server should trigger at least one scored finding"
    for f in scored:
        assert f"CVSS 3.1: {f['cvss_score']} (estimated)" in printed, f["id"]


def test_html_report_shows_the_score_and_vector_as_estimated(scanned_report):
    html = render_html(scanned_report)
    assert "CVSS 3.1 (estimated)" in html
    for f in scanned_report["findings"]:
        if f["cvss_vector"]:
            assert f["cvss_vector"] in html, f["id"]


def test_web_ui_shows_the_score_as_estimated():
    # The UI renders findings in JavaScript, so assert on the source: it must read the field
    # the API returns and label it the same way the console and HTML reports do.
    app_js = (web._STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "cvss_score" in app_js
    for line in app_js.splitlines():
        if "cvss_score" in line:
            assert "estimated" in line, line.strip()


def test_findings_that_are_not_a_weakness_carry_no_score(scanned_report):
    for f in scanned_report["findings"]:
        if f["id"] in catalog.NOT_A_WEAKNESS:
            assert f["cvss_vector"] == "" and f["cvss_score"] is None, f["id"]
