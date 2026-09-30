"""FR-DET-02: soft-404 detection by content fingerprint, including redirects to a login page."""

from __future__ import annotations

from conftest import QuietHandler

from owasp_scanner import cli, http_utils, soft404
from owasp_scanner.checks import exposure

ENV = b"APP_ENV=prod\nDB_PASSWORD=fake\n"
LISTING = b"<html><head><title>Index of /images</title></head><body><h1>Index of /images</h1></body></html>"


def _catch_all(template: bytes, real: dict[str, bytes] | None = None):
    """Answers 200 for every path with ``template`` (``{path}`` is replaced), except ``real`` paths."""
    real = real or {}

    class H(QuietHandler):
        def do_GET(self):
            path = self.path.lstrip("/")
            if path in real:
                self.send(200, real[path])
            else:
                self.send(200, template.replace(b"{path}", path.encode()))

    return H


def _redirect_all_to_login(real: dict[str, bytes] | None = None, login: bytes = b"Please sign in. Index of /"):
    real = real or {}

    class H(QuietHandler):
        def do_GET(self):
            path = self.path.lstrip("/")
            if path in real:
                self.send(200, real[path])
            elif path == "login":
                self.send(200, login)
            else:
                self.send(302, b"", {"Location": "/login"})

    return H


def _session():
    return http_utils.build_session(timeout=2, scope_host="127.0.0.1")


def test_catch_all_page_that_happens_to_match_a_signature_is_ignored(http_server):
    # The generic page has a "Contact:" line (security.txt signature) and "Index of /" text.
    base = http_server(_catch_all(b"Nothing at {path}.\nContact: support@example.com\nIndex of /"))
    profile = soft404.build_profile(_session(), base)
    assert exposure.check_sensitive_paths(_session(), base, soft404_profile=profile) == []
    assert exposure.check_directory_listing(_session(), base, soft404_profile=profile) == []


def test_catch_all_page_echoing_the_path_is_recognised(http_server):
    base = http_server(_catch_all(b"Contact: us. The page /{path} does not exist."))
    profile = soft404.build_profile(_session(), base)
    assert exposure.check_sensitive_paths(_session(), base, soft404_profile=profile) == []


def test_redirect_to_login_is_recognised(http_server):
    base = http_server(_redirect_all_to_login())
    profile = soft404.build_profile(_session(), base)
    assert exposure.check_directory_listing(_session(), base, soft404_profile=profile) == []


def test_real_files_are_still_found_on_soft_404_sites(http_server):
    base = http_server(_catch_all(b"Contact: us. Nothing at {path}.", real={".env": ENV, "images/": LISTING}))
    profile = soft404.build_profile(_session(), base)
    assert [f.id for f in exposure.check_sensitive_paths(_session(), base, soft404_profile=profile)] == ["EXPOSURE-ENV"]
    assert [f.id for f in exposure.check_directory_listing(_session(), base, soft404_profile=profile)] == [
        "EXPOSURE-DIR-LISTING"
    ]


def test_real_file_behind_login_redirects_is_still_found(http_server):
    base = http_server(_redirect_all_to_login(real={".env": ENV}))
    profile = soft404.build_profile(_session(), base)
    assert [f.id for f in exposure.check_sensitive_paths(_session(), base, soft404_profile=profile)] == ["EXPOSURE-ENV"]


def test_normal_404_site_has_an_empty_profile(http_server):
    class H(QuietHandler):
        def do_GET(self):
            self.send(404, b"not found")

    assert soft404.build_profile(_session(), http_server(H)).probes == ()


def test_probe_paths_are_random_per_scan(http_server):
    seen = []

    class H(QuietHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send(404)

    base = http_server(H)
    soft404.build_profile(_session(), base)
    soft404.build_profile(_session(), base)
    assert len(seen) == 4 and len(set(seen)) == 4
    assert any(p.endswith("/") for p in seen) and any(not p.endswith("/") for p in seen)


def test_run_scan_builds_the_profile_once(http_server):
    probes = []

    class H(QuietHandler):
        def do_GET(self):
            if "owasp-scanner-probe" in self.path:
                probes.append(self.path)
            self.send(404)

    cli.run_scan(http_server(H), timeout=5)
    assert len(probes) == 2  # shared by the sensitive-path and directory-listing checks


def test_similarity_threshold():
    a = soft404.normalize(b"The page /a does not exist. " * 20, "a")
    assert soft404.similar(a, soft404.normalize(b"The page /bbbb does not exist. " * 20, "bbbb"))
    assert not soft404.similar(a, soft404.normalize(ENV, ".env"))
