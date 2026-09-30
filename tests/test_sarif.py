"""FR-RPT-02: SARIF 2.1.0 output, built from the redacted report."""

from __future__ import annotations

import json

import pytest
from mock_server import Handler as MockHandler
from test_redact import COOKIE_SECRET, SecretHandler

from websec_scanner import __version__, cli, output, sarif


@pytest.fixture
def report(http_server):
    return output.build_report(cli.run_scan(http_server(MockHandler), timeout=5))


def test_top_level_structure(report):
    doc = sarif.to_sarif(report)
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    (run,) = doc["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Non-intrusive Web Security Scanner"
    assert driver["version"] == __version__
    assert run["invocations"][0]["executionSuccessful"] is True


def test_every_result_points_at_its_rule(report):
    run = sarif.to_sarif(report)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len({r["id"] for r in rules}) == len(rules)  # one rule per finding id
    assert len(run["results"]) == len(report["findings"])
    for result, finding in zip(run["results"], report["findings"], strict=True):
        assert result["ruleId"] == finding["id"] == rules[result["ruleIndex"]]["id"]
        assert result["partialFingerprints"] == {"websecScannerFingerprint/v1": finding["fingerprint"]}
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
            finding["url"] or report["target"]
        )


@pytest.mark.parametrize(
    "severity, level, score", [("CRITICAL", "error", "9.5"), ("HIGH", "error", "8.0"), ("MEDIUM", "warning", "5.5"),
                               ("LOW", "note", "3.0"), ("INFO", "note", "0.0")]
)  # fmt: skip
def test_severity_mapping(severity, level, score):
    finding = {
        "id": "X-Y", "title": "t", "severity": severity, "owasp_category": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693", "confidence": "high", "description": "d", "evidence": "", "recommendation": "fix it",
        "url": "https://t/", "references": ["https://owasp.org/x"], "instance_key": "k", "fingerprint": "0" * 32,
    }  # fmt: skip
    doc = sarif.to_sarif({**_empty_report(), "findings": [finding]})
    run = doc["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    assert run["results"][0]["level"] == level
    assert rule["properties"]["security-severity"] == score
    assert rule["defaultConfiguration"]["level"] == level
    assert rule["helpUri"] == "https://owasp.org/x" and rule["help"]["text"] == "fix it"
    assert "CWE-693" in rule["properties"]["tags"] and rule["properties"]["precision"] == "high"


def test_rule_severity_is_the_highest_seen_for_that_id():
    base = {"title": "t", "owasp_category": "c", "cwe": "", "confidence": "high", "description": "d", "evidence": "",
            "recommendation": "", "url": "", "references": [], "instance_key": "k"}  # fmt: skip
    findings = [
        {**base, "id": "CORS-REFLECTS-ARBITRARY-ORIGIN", "severity": "HIGH", "fingerprint": "1" * 32},
        {**base, "id": "CORS-REFLECTS-ARBITRARY-ORIGIN", "severity": "MEDIUM", "fingerprint": "2" * 32},
    ]
    run = sarif.to_sarif({**_empty_report(), "findings": findings})["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"
    assert [r["level"] for r in run["results"]] == ["error", "warning"]


def _empty_report():
    return {"target": "https://t/", "findings": [], "errors": [], "gate": {"incomplete": False}, "scan_id": "s"}


def test_errors_become_notifications_and_incomplete_scans_are_unsuccessful(closed_port):
    report = output.build_report(cli.run_scan(f"http://127.0.0.1:{closed_port}/", timeout=2))
    invocation = sarif.to_sarif(report)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["message"]["text"].startswith("Could not fetch")


def test_sarif_is_built_from_the_redacted_report(http_server):
    target = http_server(SecretHandler)
    text = json.dumps(sarif.to_sarif(output.build_report(cli.run_scan(target, timeout=5))))
    assert COOKIE_SECRET not in text


def test_cli_writes_the_sarif_file(http_server, tmp_path):
    out = tmp_path / "scan.sarif"
    cli.main([http_server(MockHandler), "--yes", "--no-color", "--sarif", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0" and doc["runs"][0]["results"]


def test_output_is_deterministic(report):
    assert json.dumps(sarif.to_sarif(report)) == json.dumps(sarif.to_sarif(report))
