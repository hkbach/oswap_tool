"""FR-RPT-08: every report says what it does not check, and never claims absolute safety."""

from __future__ import annotations

import io
from contextlib import redirect_stdout

from mock_server import Handler as MockHandler

from owasp_scanner import cli, output
from owasp_scanner.html_report import render_html
from owasp_scanner.report import print_report
from owasp_scanner.sarif import to_sarif

# Multi-word so legitimate technical terms ("Secure cookie attribute", "Transport Layer
# Security") never trip this check; CLAUDE.md names the Vietnamese phrasing, these are its
# direct English equivalents, which is what the (English-only, NFR-USA-03) output can contain.
_FORBIDDEN_PHRASES = (
    "100% secure",
    "100% detect",
    "fully secure",
    "completely secure",
    "completely safe",
    "totally safe",
    "absolutely safe",
    "guaranteed secure",
    "guarantee security",
    "risk-free",
)


def test_scope_note_names_its_own_limits():
    note = output.SCOPE_NOTE
    assert "not a full DAST" in note
    assert "does not detect real" in note
    assert "does not mean" in note.lower()  # a clean report is not a safety guarantee
    for phrase in _FORBIDDEN_PHRASES:
        assert phrase not in note.lower()


def test_console_report_includes_the_scope_note():
    report = output.build_report(cli.run_scan("http://127.0.0.1:1", timeout=1))
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        print_report(report, use_color=False)
    # print_report() wraps long lines, so compare with whitespace normalised.
    printed = " ".join(buffer.getvalue().split())
    assert " ".join(output.SCOPE_NOTE.split()) in printed


def test_html_report_footer_includes_the_scope_note():
    report = output.build_report(cli.run_scan("http://127.0.0.1:1", timeout=1))
    html = render_html(report)
    assert output.SCOPE_NOTE.split(".")[0] in html


def test_no_absolute_assurance_language_anywhere_in_a_real_scan(http_server):
    report = output.build_report(cli.run_scan(http_server(MockHandler)))
    texts = {
        "console": _captured_console(report),
        "json": str(report),
        "html": render_html(report),
        "sarif": str(to_sarif(report)),
    }
    for where, text in texts.items():
        lowered = text.lower()
        for phrase in _FORBIDDEN_PHRASES:
            assert phrase not in lowered, f"{where!r} output uses absolute-assurance language: {phrase!r}"


def _captured_console(report: dict) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        print_report(report, use_color=False)
    return buffer.getvalue()
