"""Target data printed to a terminal must not be able to control it (FR-REPORT-08).

A scanned site controls its own headers and body, and the scanner quotes them back as
evidence. Without this, a header like "nginx\\x1b[2K\\x1b[1A..." let the target erase the
findings the scanner had just printed and write its own verdict in their place: the thing
being measured could forge the measurement.
"""

from __future__ import annotations

import io
import re
from contextlib import redirect_stdout

import pytest
from conftest import QuietHandler

from websec_scanner import cli
from websec_scanner.output import build_report
from websec_scanner.report import print_report

# Everything a terminal acts on: C0 controls (except tab), DEL, and the C1 range.
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
ERASE_AND_FAKE = "nginx\x1b[2K\x1b[1A\x1b[2K No findings. Target is clean."


class Hostile(QuietHandler):
    """Puts terminal escapes everywhere the scanner quotes the target back."""

    def do_GET(self):
        if self.path == "/robots.txt":
            self.send(200, b"Disallow: /admin\x1b[2K/\n")
        else:
            self.send(
                200,
                b"home",
                [
                    ("Server", ERASE_AND_FAKE),
                    ("X-Powered-By", "php\x07\x1b]0;hijacked title\x07"),
                    ("Set-Cookie", "a\x1b[31mb=1; Path=/"),
                ],
            )


def _console(argv: list[str]) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        cli.main(argv)
    return buffer.getvalue()


def _without_our_own_colour(text: str) -> str:
    """Drop the scanner's own SGR colour codes; whatever control characters remain are the target's."""
    return re.sub(r"\x1b\[\d{0,2}m", "", text)


def test_the_target_cannot_put_control_characters_on_the_console(http_server):
    output = _console([http_server(Hostile), "--yes", "--no-color"])
    assert "nginx" in output, "the evidence should still be shown"
    leaked = CONTROL.findall(output)
    assert not leaked, f"target-controlled control characters reached the terminal: {leaked!r}"


def test_the_target_cannot_forge_a_verdict_by_erasing_lines(http_server):
    output = _console([http_server(Hostile), "--yes", "--no-color"])
    # The text may appear as inert characters, but never as a working erase sequence.
    assert "\x1b[2K" not in output and "\x1b[1A" not in output


def test_our_own_colours_still_work(http_server):
    coloured = _console([http_server(Hostile), "--yes"])
    assert "\x1b[" in coloured, "the scanner's own severity colours must survive"
    assert not CONTROL.findall(_without_our_own_colour(coloured))


def test_escapes_are_shown_as_visible_text_not_dropped_silently(http_server):
    # Hiding them entirely would let a target hide part of a value it controls.
    output = _console([http_server(Hostile), "--yes", "--no-color"])
    assert "\\x1b" in output or "\\u001b" in output


@pytest.mark.parametrize(
    "raw, printable",
    [
        ("plain", "plain"),
        ("a\x1b[31mb", "a\\x1b[31mb"),
        ("tab\there", "tab\there"),  # a tab is safe and worth keeping
        ("bell\x07", "bell\\x07"),
        ("nul\x00", "nul\\x00"),
        ("c1\x9b[2K", "c1\\x9b[2K"),  # the 8-bit CSI introducer
    ],
)
def test_control_characters_are_made_visible(raw, printable):
    from websec_scanner.report import printable_text

    assert printable_text(raw) == printable


def test_errors_from_the_target_are_also_cleaned(http_server):
    class Redirecting(QuietHandler):
        def do_GET(self):
            self.send(302, b"", [("Location", "http://other\x1b[2K.invalid/")])

    output = _console([http_server(Redirecting), "--yes", "--no-color", "--checks", "headers"])
    assert not CONTROL.findall(output)


def test_the_quiet_line_is_clean_too(http_server, capsys):
    cli.main([http_server(Hostile), "--yes", "--no-color", "--quiet"])
    captured = capsys.readouterr()
    assert not CONTROL.findall(captured.out + captured.err)


def test_the_json_report_keeps_the_real_bytes(http_server, tmp_path):
    # Only the terminal needs protecting: a machine-readable report must stay faithful, and
    # JSON encodes the control characters as escapes anyway.
    out = tmp_path / "r.json"
    cli.main([http_server(Hostile), "--yes", "--no-color", "--quiet", "--json", str(out)])
    assert "\\u001b" in out.read_text(encoding="utf-8")


def test_print_report_is_safe_for_any_report_dict():
    # Guards the helper directly, so a new printed field cannot quietly reintroduce the hole.
    from websec_scanner.models import ScanResult

    result = ScanResult(target="https://t.example/\x1b[2K", started_at="2026-10-04T00:00:00Z")
    result.errors.append("boom \x1b[1A")
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        print_report(build_report(result), use_color=False)
    assert not CONTROL.findall(buffer.getvalue())
