"""D4 / FR-AUTHZ-03 (minimum): never follow a redirect to a host outside the scan scope."""

from __future__ import annotations

import threading

import pytest
from conftest import QuietHandler

from owasp_scanner import cli, http_utils


class CountingHandler(QuietHandler):
    """The out-of-scope server: it must never receive a request."""

    hits: list[str] = []
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            self.hits.append(self.path)
        self.send(200, b"outside")


@pytest.fixture
def outside(http_server):
    """An HTTP server reachable as 'localhost', i.e. a different host than 127.0.0.1."""
    CountingHandler.hits = []
    base = http_server(CountingHandler)
    return base.replace("127.0.0.1", "localhost"), CountingHandler.hits


def _redirecting_handler(location_for):
    class H(QuietHandler):
        def do_GET(self):
            location = location_for(self.path)
            if location:
                self.send(302, b"", {"Location": location})
            else:
                self.send(200, b"home", {"Content-Type": "text/html"})

    return H


@pytest.mark.parametrize(
    "url, scope, expected",
    [
        ("https://example.com/", "example.com", True),
        ("https://www.example.com:8443/x", "example.com", True),  # www prefix and port may change
        ("http://Example.COM/", "www.example.com", True),
        ("https://api.example.com/", "example.com", False),  # other subdomains are out of scope
        ("https://example.com.evil.net/", "example.com", False),
        ("https://evil.net/?next=example.com", "example.com", False),
        ("http://127.0.0.1:8080/", "127.0.0.1", True),
        ("http://localhost/", "127.0.0.1", False),
    ],
)
def test_in_scope(url, scope, expected):
    assert http_utils.in_scope(url, scope) is expected


def test_session_follows_at_most_ten_redirects():
    assert http_utils.build_session(scope_host="example.com").max_redirects == 10


def test_baseline_redirect_to_other_host_is_not_followed(http_server, outside):
    outside_base, hits = outside
    target = http_server(_redirecting_handler(lambda path: outside_base if path == "/" else None))
    result = cli.run_scan(target, timeout=5)

    assert hits == []  # no request ever reached the out-of-scope host
    blocked = [e for e in result.errors if "outside the scan scope" in e]
    assert len(blocked) == 1 and "localhost" in blocked[0]
    assert "security-headers" in result.checks_run  # the scan went on with the last in-scope response


def test_path_redirects_to_other_host_are_blocked_and_reported_once(http_server, outside):
    outside_base, hits = outside
    target = http_server(_redirecting_handler(lambda path: None if path == "/" else outside_base + path.lstrip("/")))
    result = cli.run_scan(target, timeout=5)

    assert hits == []
    assert not [f for f in result.findings if f.id.startswith("EXPOSURE-") and f.id != "EXPOSURE-DIR-LISTING"]
    assert len([e for e in result.errors if "outside the scan scope" in e]) == 1  # one line, not one per path


def test_in_scope_redirects_are_followed(http_server):
    target = http_server(_redirecting_handler(lambda path: "/home" if path == "/" else None))
    session = http_utils.build_session(timeout=5, scope_host="127.0.0.1")
    resp, err = http_utils.safe_get(session, target)
    assert err is None and resp.url.endswith("/home") and resp.status_code == 200
    assert session.blocked_redirects == {}


def test_redirect_to_another_port_on_the_same_host_is_followed(http_server):
    other = http_server(_redirecting_handler(lambda path: None))
    target = http_server(_redirecting_handler(lambda path: other if path == "/" else None))
    session = http_utils.build_session(timeout=5, scope_host="127.0.0.1")
    resp, err = http_utils.safe_get(session, target)
    assert err is None and resp.url == other


def test_session_without_scope_follows_everything(http_server, outside):
    outside_base, hits = outside
    target = http_server(_redirecting_handler(lambda path: outside_base))
    resp, err = http_utils.safe_get(http_utils.build_session(timeout=5), target)
    assert err is None and hits  # backwards compatible for callers that do not set a scope
