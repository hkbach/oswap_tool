"""The CLI must reject a target it cannot scan, with the same rule as the Web UI (FR-CLI-07).

Before this, `websec-scanner ftp://host/` printed the consent banner, ran an empty scan and
exited 3 with "No connection adapters were found for 'ftp://...'" buried in the report, while
the Web UI rejected the same target with a clear 400 (FR-UI-04).
"""

from __future__ import annotations

import pytest

from websec_scanner import cli


@pytest.mark.parametrize(
    "target, normalised",
    [
        ("example.com", "https://example.com/"),  # bare host gets https://
        ("example.com/app", "https://example.com/app/"),
        ("http://example.com", "http://example.com/"),
        ("https://example.com:8443/a?b=1", "https://example.com:8443/a/?b=1"),
        ("HTTP://Example.COM/", "http://Example.COM/"),  # the scheme normalises, the host keeps its case
        ("127.0.0.1:8080", "https://127.0.0.1:8080/"),
        ("[::1]:8443", "https://[::1]:8443/"),
    ],
)
def test_a_usable_target_is_normalised(target, normalised):
    assert cli._normalize_target(target) == normalised


@pytest.mark.parametrize(
    "target, reason",
    [
        ("ftp://example.com/", "http"),  # a scheme the scanner cannot speak
        ("gopher://example.com/", "http"),
        ("file:///etc/passwd", "http"),
        ("javascript:alert(1)", "http"),  # would otherwise become https://javascript:alert(1)/
        ("data:text/html,x", "http"),
        ("http://", "host"),  # a scheme with no host
        ("https:///path", "host"),
        ("://nohost", "http"),
        ("", "empty"),
        ("   ", "empty"),
    ],
)
def test_a_target_that_cannot_be_scanned_is_rejected(target, reason):
    with pytest.raises(ValueError, match=reason):
        cli._normalize_target(target)


def test_the_cli_refuses_before_printing_the_banner(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["ftp://example.com/", "--yes"])
    assert exc.value.code == 2  # a usage error, not an exit-3 "could not scan"
    captured = capsys.readouterr()
    assert "http://" in captured.err and "ftp://example.com/" in captured.err
    assert captured.out == "", "nothing should be printed before the target is known to be usable"


def test_a_bad_entry_in_a_targets_file_names_the_file_and_the_entry(tmp_path, capsys):
    listing = tmp_path / "targets.txt"
    listing.write_text("https://ok.example/\nftp://bad.example/\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        cli.main(["--targets-file", str(listing), "--yes"])
    err = capsys.readouterr().err
    assert "targets.txt" in err and "ftp://bad.example/" in err


def test_the_cli_and_the_web_ui_accept_exactly_the_same_targets():
    # FR-UI-04 and FR-CLI-07 must not drift apart: the web UI rejects a target when the
    # normalised scheme is not http/https or there is no hostname.
    from urllib.parse import urlsplit

    for target in ("example.com", "http://h/", "https://h:8443/a", "127.0.0.1:8080", "[::1]:443"):
        parts = urlsplit(cli._normalize_target(target))
        assert parts.scheme.lower() in ("http", "https") and parts.hostname
    for target in ("ftp://h/", "file:///x", "javascript:alert(1)", "http://", "gopher://h/"):
        with pytest.raises(ValueError):
            cli._normalize_target(target)
