"""A broken or hostile server must not crash the scanner (NFR-REL-01).

A server controls its own headers. `Location: http://evil[.invalid/` made urljoin() raise
ValueError, which nothing caught, so the whole scan died with a traceback instead of
reporting the bad redirect and carrying on.
"""

from __future__ import annotations

import pytest
from conftest import QuietHandler

from websec_scanner import cli
from websec_scanner.http_utils import build_session

MALFORMED_LOCATIONS = [
    "http://evil[.invalid/",  # an unterminated IPv6 literal
    "http://[::1/",
    "http://[fe80::1%25eth0]:notaport/",
    "http://host:99999999999999/",
    "//evil[.invalid/",
    "\x00http://evil.invalid/",
]


@pytest.mark.parametrize("location", MALFORMED_LOCATIONS)
def test_a_malformed_redirect_does_not_crash_the_scan(http_server, location):
    class Redirecting(QuietHandler):
        def do_GET(self):
            self.send(302, b"", [("Location", location)])

    result = cli.run_scan(http_server(Redirecting), groups=["headers"])
    assert result.target  # it got far enough to produce a result at all
    assert not [e for e in result.errors if "Traceback" in e]


@pytest.mark.parametrize("location", MALFORMED_LOCATIONS)
def test_a_malformed_redirect_is_reported_not_followed_silently(http_server, location):
    class Redirecting(QuietHandler):
        def do_GET(self):
            self.send(302, b"", [("Location", location)])

    result = cli.run_scan(http_server(Redirecting), groups=["headers"])
    assert any("redirect" in e.lower() for e in result.errors), result.errors


def test_the_session_treats_an_unparseable_location_as_not_followable():
    import requests
    from requests.structures import CaseInsensitiveDict

    session = build_session(scope_host="t.example")
    response = requests.Response()
    response.url = "https://t.example/"
    response.status_code = 302
    response.headers = CaseInsensitiveDict({"Location": "http://evil[.invalid/"})

    assert session.get_redirect_target(response) is None
    assert session.blocked_redirects, "the refusal should be recorded for the report"
    assert "not a usable URL" in " ".join(session.blocked_redirects.values())
