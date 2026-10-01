"""FR-AUTHZ-03, FR-AUTHZ-06, FR-AUTHZ-09: what the scanner refuses to touch, and how it signs its traffic."""

from __future__ import annotations

import re

import pytest
from conftest import QuietHandler
from mock_server import Handler as MockHandler

from websec_scanner import cli, rule_loader
from websec_scanner.http_utils import build_session, in_scope


class RecordingHandler(QuietHandler):
    """Records the path and the scanner headers of every request it receives."""

    seen: list[tuple[str, str | None]] = []

    def do_GET(self):
        type(self).seen.append((self.path, self.headers.get("X-Scanner-Scan-Id")))
        self.send(200, b"home")


@pytest.fixture
def recording_server(http_server):
    RecordingHandler.seen = []
    return http_server(RecordingHandler), RecordingHandler


# --- FR-AUTHZ-06: exclusions -------------------------------------------------


@pytest.mark.parametrize(
    "path, excluded",
    [
        ("/logout", True),
        ("/user/sign-out/", True),
        ("/account/delete", True),
        ("/checkout/step-2", True),
        ("/reset-password?token=x", True),
        ("/admin/shutdown", True),
        ("/LOGOUT", True),  # the built-in patterns are case-insensitive
        ("/about", False),
        ("/blog/how-we-delete-data", False),  # "delete" mid-word is not a delete action
        ("/", False),
    ],
)
def test_the_built_in_exclusions_cover_state_changing_paths(path, excluded):
    session = build_session(scope_host="t.example", exclusions=rule_loader.load_exclusions().patterns)
    assert session.is_excluded(f"https://t.example{path}") is excluded


def test_a_user_pattern_is_added_to_the_built_in_ones():
    session = build_session(
        scope_host="t.example",
        exclusions=[*rule_loader.load_exclusions().patterns, re.compile("/private", re.IGNORECASE)],
    )
    assert session.is_excluded("https://t.example/private/files")
    assert session.is_excluded("https://t.example/logout")


def test_an_excluded_host_is_never_requested():
    session = build_session(scope_host="t.example", excluded_hosts=["cdn.example"])
    assert session.is_excluded("https://cdn.example/a")
    assert not session.is_excluded("https://t.example/a")


def test_excluded_paths_are_not_requested_during_a_scan(recording_server):
    url, handler = recording_server
    cli.run_scan(url, exclude=["/images/"], groups=["directory-listing"])
    assert handler.seen, "the scan should still have requested something"
    assert not [path for path, _ in handler.seen if path.startswith("/images/")]


def test_the_report_says_what_was_excluded(recording_server):
    url, _ = recording_server
    result = cli.run_scan(url, exclude=["/images/"], groups=["directory-listing"])
    assert any("excluded" in e for e in result.errors), result.errors


def test_default_excludes_can_be_turned_off():
    session = build_session(scope_host="t.example", exclusions=[])
    assert not session.is_excluded("https://t.example/logout")


def test_an_invalid_exclusion_regex_is_rejected_before_any_request(http_server, capsys):
    with pytest.raises(SystemExit):
        cli.main([http_server(MockHandler), "--yes", "--no-color", "--exclude", "([unclosed"])
    assert "invalid regular expression" in capsys.readouterr().err


def test_a_redirect_into_an_excluded_path_is_not_followed(http_server):
    class RedirectToLogout(QuietHandler):
        def do_GET(self):
            if self.path == "/":
                self.send(302, b"", [("Location", "/logout")])
            else:
                type(self).reached_logout = True
                self.send(200, b"bye")

    RedirectToLogout.reached_logout = False
    cli.run_scan(http_server(RedirectToLogout), groups=["headers"])
    assert not RedirectToLogout.reached_logout, "the scanner followed a redirect into an excluded path"


# --- FR-AUTHZ-03: declared scope ---------------------------------------------


def test_scope_is_the_target_host_by_default():
    assert in_scope("https://t.example/a", "t.example")
    assert in_scope("https://www.t.example/a", "t.example")  # D4: www. prefix only
    assert not in_scope("https://other.example/a", "t.example")


def test_a_declared_host_widens_the_scope():
    assert in_scope("https://api.t.example/a", "t.example", ["api.t.example"])
    assert not in_scope("https://evil.example/a", "t.example", ["api.t.example"])


def test_a_declared_host_is_followed_through_a_redirect(http_server):
    session = build_session(scope_host="t.example", allowed_hosts=["api.t.example"])
    assert session.allowed_hosts == frozenset({"api.t.example"})


def test_an_undeclared_host_is_still_blocked_and_reported(http_server):
    class RedirectAway(QuietHandler):
        def do_GET(self):
            self.send(302, b"", [("Location", "https://not-in-scope.invalid/")])

    result = cli.run_scan(http_server(RedirectAway), groups=["headers"])
    assert any("not-in-scope.invalid" in e and "outside the scan scope" in e for e in result.errors), result.errors


# --- FR-AUTHZ-09: scan id header ---------------------------------------------


def test_the_scan_id_header_is_off_by_default(recording_server):
    url, handler = recording_server
    cli.run_scan(url, groups=["directory-listing"])
    assert handler.seen
    assert all(scan_id is None for _, scan_id in handler.seen)


def test_the_scan_id_header_carries_the_scan_id_when_asked(recording_server):
    url, handler = recording_server
    result = cli.run_scan(url, send_scan_id=True, groups=["directory-listing"])
    assert handler.seen
    assert {scan_id for _, scan_id in handler.seen} == {result.scan_id}
