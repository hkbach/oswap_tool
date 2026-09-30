"""SARIF 2.1.0 export of a scan report (FR-RPT-02).

Built from the dict of output.build_report(), so secrets are already redacted and the
content matches the JSON report. One rule per finding id, one result per finding;
``partialFingerprints`` carries the finding fingerprint so code-scanning tools can
track a finding across scans. Results point at the scanned URL, not at a file in a
repository, because this is a web scanner.
"""

from __future__ import annotations

from . import __version__
from .models import SEVERITY_ORDER

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "OWASP-Aligned Non-intrusive Web Security Scanner"
TOOL_URI = "https://github.com/hkbach/oswap_tool"
FINGERPRINT_KEY = "owaspScannerFingerprint/v1"

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
# GitHub code scanning reads "security-severity" (0.0-10.0) to rank security results.
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}
_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}


def _rule(finding: dict, severity: str) -> dict:
    tags = ["security", *(t for t in (finding.get("owasp_category"), finding.get("cwe")) if t)]
    rule = {
        "id": finding["id"],
        "shortDescription": {"text": finding["title"]},
        "fullDescription": {"text": finding["description"]},
        "defaultConfiguration": {"level": _LEVEL.get(severity, "note")},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY.get(severity, "0.0"),
            "precision": finding.get("confidence") or "medium",
        },
    }
    if finding.get("references"):
        rule["helpUri"] = finding["references"][0]
    if finding.get("recommendation"):
        rule["help"] = {"text": finding["recommendation"]}
    return rule


def _result(finding: dict, rule_index: int, target: str) -> dict:
    message = f"{finding['title']}: {finding['description']}"
    if finding.get("evidence"):
        message += f" Evidence: {finding['evidence']}"
    return {
        "ruleId": finding["id"],
        "ruleIndex": rule_index,
        "level": _LEVEL.get(finding["severity"], "note"),
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.get("url") or target}}}],
        "partialFingerprints": {FINGERPRINT_KEY: finding["fingerprint"]},
        "properties": {
            "severity": finding["severity"],
            "confidence": finding.get("confidence", ""),
            "instance_key": finding.get("instance_key", ""),
        },
    }


def to_sarif(report: dict) -> dict:
    findings = report.get("findings", [])
    # One rule per id, with the highest severity seen for it (e.g. CORS reflection is HIGH or MEDIUM).
    worst: dict[str, dict] = {}
    for finding in findings:
        current = worst.get(finding["id"])
        if current is None or _RANK.get(finding["severity"], 9) < _RANK.get(current["severity"], 9):
            worst[finding["id"]] = finding
    order = list(dict.fromkeys(f["id"] for f in findings))
    rules = [_rule(worst[rule_id], worst[rule_id]["severity"]) for rule_id in order]
    index = {rule_id: i for i, rule_id in enumerate(order)}

    run = {
        "tool": {"driver": {"name": TOOL_NAME, "version": __version__, "informationUri": TOOL_URI, "rules": rules}},
        "invocations": [
            {
                "executionSuccessful": not report.get("gate", {}).get("incomplete", False),
                "toolExecutionNotifications": [
                    {"level": "warning", "message": {"text": error}} for error in report.get("errors", [])
                ],
            }
        ],
        "results": [_result(f, index[f["id"]], report.get("target", "")) for f in findings],
        "properties": {
            key: report[key]
            for key in ("target", "final_url", "scan_id", "schema_version", "rules_version", "gate")
            if key in report
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
