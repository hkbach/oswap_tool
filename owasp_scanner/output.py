"""The single output pipeline shared by the CLI and the Web UI (FR-WEB-01).

Everything that turns a ScanResult into what users see — the report dict, the
pass/fail gate — happens here, so the console output, ``--json``, the Web UI
response and the HTML report cannot drift apart.
"""

from __future__ import annotations

from .models import ScanResult

GATE_SEVERITIES = ("CRITICAL", "HIGH")  # FR-CLI-04: any of these fails the gate


def build_report(result: ScanResult) -> dict:
    """The report dict (SRS 6.2) every output format is rendered from."""
    return result.to_dict()


def gate_failed(report: dict) -> bool:
    """True when the report fails the CI gate: CLI exit code 1, Web UI ``gate_failed``."""
    return any(report["summary"].get(sev, 0) for sev in GATE_SEVERITIES)
