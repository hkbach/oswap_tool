"""The single output pipeline shared by the CLI and the Web UI (FR-WEB-01).

Everything that turns a ScanResult into what users see — the report dict, secret
redaction, the pass/fail gate — happens here, so the console output, ``--json``,
the Web UI response and the HTML report cannot drift apart.
"""

from __future__ import annotations

from .models import ScanResult
from .redact import redact

GATE_SEVERITIES = ("CRITICAL", "HIGH")  # FR-CLI-04: any of these fails the gate
_REDACTED_FINDING_FIELDS = ("title", "description", "evidence", "url", "instance_key")


def build_report(result: ScanResult, *, show_secrets: bool = False) -> dict:
    """The report dict (SRS 6.2) every output format is rendered from.

    Secrets are redacted unless ``show_secrets`` is true (D2). Only the CLI may pass
    ``show_secrets=True`` (``--show-secrets``); the Web UI never does.
    """
    report = result.to_dict()
    report["secrets_redacted"] = not show_secrets
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


def gate_failed(report: dict) -> bool:
    """True when the report fails the CI gate: CLI exit code 1, Web UI ``gate_failed``."""
    return any(report["summary"].get(sev, 0) for sev in GATE_SEVERITIES)
