"""The single output pipeline shared by the CLI and the Web UI (FR-WEB-01).

Everything that turns a ScanResult into what users see — the report dict, secret
redaction, the pass/fail gate — happens here, so the console output, ``--json``,
the Web UI response and the HTML report cannot drift apart.
"""

from __future__ import annotations

from .catalog import CHECK_GROUPS, group_of_check
from .models import SEVERITY_ORDER, ScanResult
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
# FR-RPT-08: every report must say what it does not check and must not claim absolute safety
# (CLAUDE.md: no "đảm bảo an toàn" / "phát hiện 100%" — no "guaranteed safe" / "detects
# everything" in English either). One wording, shared by the console report and the HTML
# report so they cannot drift apart.
SCOPE_NOTE = (
    "This is a non-intrusive configuration check, not a full DAST assessment: it does not "
    "detect real SQL injection/XSS, business-logic flaws or application-level authentication "
    "issues. A clean report does not mean the target is secure: it means these checks found "
    "nothing. Only scan systems you own or are explicitly authorized to test."
)
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

    # Findings can share a fingerprint (the same cookie set on a redirect hop and on the final
    # response), so collect the pairs of all of them instead of keeping only the last.
    pairs_by_fingerprint: dict[str, list[tuple[str, str]]] = {}
    for f in result.findings:
        pairs_by_fingerprint.setdefault(f.fingerprint, []).extend(f.redactions)
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


def gate_message(gate: dict) -> tuple[str, str]:
    """``(status, text)`` shown for a report's ``gate`` by the HTML report and the Web UI.

    ``status`` is ``"fail"``, ``"warn"`` (scan incomplete) or ``"pass"``; the text names the
    threshold and the CLI exit code, so both views say the same thing.
    """
    threshold = f"--fail-on {gate['fail_on']}"
    if gate["failed"]:
        return "fail", f"Findings at or above the {threshold} threshold: the CLI exits with code 1 (fails the CI gate)."
    if gate["incomplete"]:
        code = "0 (--fail-on none)" if gate["fail_on"] == "none" else "3"
        return (
            "warn",
            f"The target home page could not be fetched, so most checks did not run. The CLI exits with code {code}. "
            "See the errors below.",
        )
    if gate["fail_on"] == "none":
        return "pass", "--fail-on none: the gate never fails; the CLI exits with code 0."
    return "pass", f"No findings at or above the {threshold} threshold: the CLI exits with code 0."


def _counts(findings: list[dict], indexes: list[int]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for i in indexes:
        counts[findings[i]["severity"]] = counts.get(findings[i]["severity"], 0) + 1
    return counts


def group_findings(report: dict) -> list[dict]:
    """The report's findings by test target (catalog.CHECK_GROUPS), for the HTML report and the Web UI.

    One entry per group, in table order: ``id``, ``title``, ``description``, ``status``,
    ``counts`` (per severity) and ``findings`` (indexes into ``report["findings"]``, in
    report order). ``status`` is ``issues``, ``clean`` (ran, nothing found), ``not-run``
    (selected but none of its checks ran, e.g. TLS on an http:// target) or ``not-selected``.
    """
    findings = report["findings"]
    selected = set(report["scan_groups"])
    ran = set(report["checks_run"])
    groups = []
    for group in CHECK_GROUPS:
        indexes = [i for i, f in enumerate(findings) if group_of_check(f["check"]) == group.id]
        if indexes:
            status = "issues"
        elif group.id not in selected:
            status = "not-selected"
        elif ran.intersection(group.checks):
            status = "clean"
        else:
            status = "not-run"
        groups.append(
            {
                "id": group.id,
                "title": group.title,
                "description": group.description,
                "status": status,
                "counts": _counts(findings, indexes),
                "findings": indexes,
            }
        )
    return groups


def owasp_groups(report: dict) -> list[dict]:
    """The report's findings by OWASP Top 10 category, sorted by category; only categories found.

    Each entry has ``id`` (e.g. ``A05:2021``), ``title`` (the full ``owasp_category``),
    ``counts`` and ``findings`` (indexes into ``report["findings"]``).
    """
    findings = report["findings"]
    by_category: dict[str, list[int]] = {}
    for i, f in enumerate(findings):
        by_category.setdefault(f.get("owasp_category") or "Unclassified", []).append(i)
    return [
        {"id": title.split(" - ", 1)[0], "title": title, "counts": _counts(findings, indexes), "findings": indexes}
        for title, indexes in sorted(by_category.items())
    ]


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
