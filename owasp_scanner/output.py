"""The single output pipeline shared by the CLI and the Web UI (FR-WEB-01).

Everything that turns a ScanResult into what users see — the report dict, secret
redaction, the pass/fail gate — happens here, so the console output, ``--json``,
the Web UI response and the HTML report cannot drift apart.
"""

from __future__ import annotations

from .models import ScanResult
from .redact import redact

# FR-CI-01: --fail-on threshold -> severities that fail the gate (default "high" = FR-CLI-04).
FAIL_ON_SEVERITIES = {
    "critical": ("CRITICAL",),
    "high": ("CRITICAL", "HIGH"),
    "medium": ("CRITICAL", "HIGH", "MEDIUM"),
    "low": ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
    "none": (),
}
FAIL_ON_CHOICES = tuple(FAIL_ON_SEVERITIES)
DEFAULT_FAIL_ON = "high"
_REDACTED_FINDING_FIELDS = ("title", "description", "evidence", "url", "instance_key")


def build_report(result: ScanResult, *, show_secrets: bool = False, fail_on: str = DEFAULT_FAIL_ON) -> dict:
    """The report dict (SRS 6.2) every output format is rendered from.

    Secrets are redacted unless ``show_secrets`` is true (D2). Only the CLI may pass
    ``show_secrets=True`` (``--show-secrets``); the Web UI never does.
    """
    report = result.to_dict()
    report["secrets_redacted"] = not show_secrets
    report["gate"] = {
        "fail_on": fail_on,
        "failed": gate_failed(report, fail_on),
        "incomplete": not result.baseline_fetched,  # the home page could not be fetched
    }
    if show_secrets:
        return report

    pairs_by_fingerprint = {f.fingerprint: f.redactions for f in result.findings}
    report["target"] = redact(report["target"])
    report["final_url"] = redact(report["final_url"])
    report["redirect_chain"] = [dict(hop, url=redact(hop["url"])) for hop in report["redirect_chain"]]
    report["errors"] = [redact(error) for error in report["errors"]]
    for finding in report["findings"]:
        pairs = pairs_by_fingerprint.get(finding["fingerprint"], ())
        for key in _REDACTED_FINDING_FIELDS:
            finding[key] = redact(finding[key], pairs)
    return report


def gate_failed(report: dict, fail_on: str = DEFAULT_FAIL_ON) -> bool:
    """True when a finding is at or above the ``fail_on`` threshold (CLI exit code 1, Web UI ``gate_failed``)."""
    return any(report["summary"].get(sev, 0) for sev in FAIL_ON_SEVERITIES[fail_on])


def exit_code(report: dict) -> int:
    """FR-CLI-04 / FR-CI-01: 1 = gate failed, 3 = scan incomplete, 0 = pass (2 = no consent, set by the CLI).

    Findings over the threshold win over "incomplete": an expired certificate that
    made the home page unreachable is reported as the failure it is.
    """
    gate = report["gate"]
    if gate["failed"]:
        return 1
    if gate["incomplete"] and gate["fail_on"] != "none":
        return 3
    return 0
