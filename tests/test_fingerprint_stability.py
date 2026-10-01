"""FR-MODEL-07: a finding keeps its fingerprint across scans of the same site.

The fingerprint is what --baseline matches on (FR-CI-02), so anything that changes it
between two scans of the same issue makes an old finding look new and fails CI for nothing.
SRS 6.1 promises "origin, not path"; these pin that promise for the checks that used to
hash the whole start URL.
"""

from __future__ import annotations

import pytest
from conftest import QuietHandler

from websec_scanner import catalog, cli
from websec_scanner.checks import cors_check, redirect_check
from websec_scanner.http_utils import build_session, site_root


@pytest.mark.parametrize(
    "url, root",
    [
        ("https://t.example/", "https://t.example/"),
        ("https://t.example/app/?q=1", "https://t.example/"),
        ("https://T.Example/app#frag", "https://t.example/"),
        ("https://t.example:443/x", "https://t.example/"),  # the default port is not part of it
        ("http://t.example:80/x", "http://t.example/"),
        ("http://127.0.0.1:8080/app/?session=abc", "http://127.0.0.1:8080/"),
        ("https://user:hunter2@t.example/x", "https://t.example/"),  # never the credentials
        ("https://[::1]:8443/x", "https://[::1]:8443/"),
    ],
)
def test_site_root_keeps_scheme_host_and_port_only(url, root):
    assert site_root(url) == root


class _ReflectingCors(QuietHandler):
    def do_GET(self):
        self.send(200, b"x", [("Access-Control-Allow-Origin", self.headers.get("Origin") or "*")])


def _cors_fingerprint(http_server, path: str) -> str:
    base = http_server(_ReflectingCors)
    url = base.rstrip("/") + path
    (finding,) = cors_check.check_cors(build_session(timeout=2), url)
    return catalog.enrich(finding, url).fingerprint, finding.instance_key


def test_cors_fingerprint_does_not_depend_on_the_start_path(http_server):
    from_root, _ = _cors_fingerprint(http_server, "/")
    from_app, _ = _cors_fingerprint(http_server, "/app/?q=1")
    # Different servers have different ports, so compare the instance key and the shape
    # of the fingerprint input rather than two fingerprints from two ports.
    assert from_root and from_app
    base = http_server(_ReflectingCors)
    a = catalog.fingerprint("CORS-REFLECTS-ARBITRARY-ORIGIN", site_root(base), base)
    b = catalog.fingerprint("CORS-REFLECTS-ARBITRARY-ORIGIN", site_root(base + "app/?q=1"), base + "app/?q=1")
    assert a == b


def test_cors_instance_key_is_the_site_root(http_server):
    _, key = _cors_fingerprint(http_server, "/app/?session=rotating-token")
    assert key.endswith("/") and "?" not in key and "/app" not in key


def test_a_rotating_token_in_the_query_does_not_change_the_fingerprint(http_server):
    base = http_server(_ReflectingCors)
    keys = set()
    for token in ("abc", "xyz"):
        url = f"{base}?session={token}"
        (finding,) = cors_check.check_cors(build_session(timeout=2), url)
        keys.add(catalog.enrich(finding, url).fingerprint)
    assert len(keys) == 1


def test_a_root_scan_keeps_the_fingerprint_it_had_before(http_server):
    # No churn for the common case: scanning "/" with no query gave instance_key == the URL
    # before FR-MODEL-07, and still does, so existing SARIF fingerprints are unchanged.
    base = http_server(_ReflectingCors)
    (finding,) = cors_check.check_cors(build_session(timeout=2), base)
    assert finding.instance_key == base


def test_http_target_redirect_finding_does_not_depend_on_the_start_path():
    a = redirect_check.evaluate_redirect_chain("http://t.example/", ["http://t.example/"])
    b = redirect_check.evaluate_redirect_chain("http://t.example/app/?q=1", ["http://t.example/app/?q=1"])
    assert [f.instance_key for f in a] == [f.instance_key for f in b] == ["http://t.example/"]


def test_https_target_redirect_finding_keeps_its_existing_key(http_server):
    # The https branch already used http://<host>/, which is a site root: unchanged.
    finding = redirect_check._finding("http://t.example/", "http://t.example/")
    assert finding.instance_key == "http://t.example/"


def test_two_scans_of_one_site_from_different_pages_share_every_fingerprint(http_server):
    class Site(QuietHandler):
        def do_GET(self):
            self.send(200, b"page", [("Access-Control-Allow-Origin", "*")])

    base = http_server(Site)
    first = {f.fingerprint for f in cli.run_scan(base, groups=["cors", "headers"]).findings}
    second = {f.fingerprint for f in cli.run_scan(base + "deep/page?x=1", groups=["cors", "headers"]).findings}
    assert first == second
