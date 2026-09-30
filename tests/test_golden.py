"""FR-QA-02: golden files for the JSON, SARIF and HTML reports.

One CLI run against the mock server writes all three reports. Values that change
on every run (scan id, timestamps, the mock server's port, the scanner version and
the port-dependent fingerprints) are replaced by placeholders, then each report is
compared with tests/golden/. Any other change in the output fails the test.

After an intended output change, regenerate the files and review the diff:

    UPDATE_GOLDEN=1 python -m pytest tests/test_golden.py
"""

from __future__ import annotations

import json
import os
import re
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from conftest import _start
from mock_server import Handler as MockHandler

from owasp_scanner import __version__, cli

GOLDEN = Path(__file__).resolve().parent / "golden"
FORMATS = ("json", "sarif", "html")
# Fake secrets served by the mock server; no report may contain them.
MOCK_SECRETS = ("abc123", "hunter2")


class FixedVersionHandler(MockHandler):
    """The mock server, with a Server header that does not depend on the Python version."""

    def version_string(self) -> str:
        return "MockServer/1.0"


@pytest.fixture(scope="module")
def reports(tmp_path_factory) -> dict[str, str]:
    server = _start(ThreadingHTTPServer(("127.0.0.1", 0), FixedVersionHandler))
    out = tmp_path_factory.mktemp("golden")
    paths = {fmt: out / f"report.{fmt}" for fmt in FORMATS}
    try:
        target = f"http://127.0.0.1:{server.server_address[1]}/"
        args = [target, "--yes", "--no-color", *[a for fmt, p in paths.items() for a in (f"--{fmt}", str(p))]]
        assert cli.main(args) == 1  # the mock server has HIGH findings
    finally:
        server.shutdown()
        server.server_close()
    texts = {fmt: p.read_text(encoding="utf-8") for fmt, p in paths.items()}
    return _normalise(texts, json.loads(texts["json"]), server.server_address[1])


def _normalise(texts: dict[str, str], report: dict, port: int) -> dict[str, str]:
    replacements = {
        report["scan_id"]: "<SCAN_ID>",
        report["started_at"]: "<STARTED_AT>",
        report["finished_at"]: "<FINISHED_AT>",
        f"127.0.0.1:{port}": "127.0.0.1:<PORT>",
    }
    for finding in report["findings"]:
        assert re.fullmatch(r"[0-9a-f]{32}", finding["fingerprint"])
        replacements[finding["fingerprint"]] = "<FINGERPRINT>"
    result = {}
    for fmt, text in texts.items():
        for old, new in replacements.items():
            text = text.replace(old, new)
        # The version changes on every release; replace it last so it cannot hit a replaced value.
        result[fmt] = re.sub(rf"(?<![\d.]){re.escape(__version__)}(?![\d.])", "<VERSION>", text)
    return result


@pytest.mark.parametrize("fmt", FORMATS)
def test_report_matches_the_golden_file(reports, fmt):
    golden = GOLDEN / f"mock_server.{fmt}"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        golden.parent.mkdir(exist_ok=True)
        golden.write_text(reports[fmt], encoding="utf-8", newline="\n")
    assert golden.exists(), f"missing {golden.name}; run with UPDATE_GOLDEN=1 to create it"
    assert reports[fmt] == golden.read_text(encoding="utf-8"), (
        f"{fmt} report differs from tests/golden/{golden.name}; if the change is intended, "
        "regenerate with UPDATE_GOLDEN=1 and review the diff"
    )


@pytest.mark.parametrize("fmt", FORMATS)
def test_report_has_no_run_specific_values_left(reports, fmt):
    assert not re.search(r"\b20\d\d-\d\d-\d\dT", reports[fmt]), "a timestamp was not normalised"
    assert not re.search(r"127\.0\.0\.1:\d", reports[fmt]), "a port was not normalised"


@pytest.mark.parametrize("fmt", FORMATS)
def test_report_does_not_leak_the_mock_secrets(reports, fmt):
    for secret in MOCK_SECRETS:
        assert secret not in reports[fmt]
