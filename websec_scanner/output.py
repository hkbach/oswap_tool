"""The single output pipeline shared by the CLI and the Web UI (FR-WEB-01).

Everything that turns a ScanResult into what users see — the report dict, secret
redaction, the pass/fail gate — happens here, so the console output, ``--json``,
the Web UI response and the HTML report cannot drift apart.
"""

from __future__ import annotations

from collections.abc import Iterable

from . import models
from .baseline import Baseline, compare
from .catalog import CHECK_GROUPS, group_of_check
from .models import SEVERITY_ORDER, ScanResult
from .redact import redact
from .suppressions import Suppressions

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
# (CLAUDE.md: no "guaranteed safe" / "detects 100%" / "detects everything" claims). One
# wording, shared by the console report and the HTML report so they cannot drift apart.
SCOPE_NOTE = (
    "This is a non-intrusive configuration check, not a full DAST assessment: it does not "
    "detect real SQL injection/XSS, business-logic flaws or application-level authentication "
    "issues. A clean report does not mean the target is secure: it means these checks found "
    "nothing. Only scan systems you own or are explicitly authorized to test."
)
# FR-MODEL-03: one wording for what a CVSS score in this report does and does not mean,
# shared by the console and HTML reports. Shown only when a report actually carries scores.
CVSS_NOTE = (
    "CVSS 3.1 base scores in this report are estimated for the type of finding, not assessed for "
    "this target, and they are a separate scale from the severity column: a finding can be CRITICAL "
    "here and still score below 9.0, because severity also weighs how directly the issue was "
    "observed and how easily it can be abused in context. Findings that are not a scorable "
    "weakness (early warnings, hints, informational observations) carry no score at all."
)
# FR-SPEC-05: endpoints listed on the console and in the HTML report; the JSON report has every one.
API_LISTED_ENDPOINTS = 100
# FR-CRAWL-01: how a crawl's stop reason and skipped links are worded, shared by the console and HTML reports.
CRAWL_STOP_TEXT = {
    "complete": "all reachable pages were visited",
    "max-depth": "stopped at --crawl-depth: links beyond it were not followed",
    "max-pages": "stopped at --crawl-max-pages",
    "max-duration": "stopped at --crawl-max-duration",
    "scan-limit": "stopped by --max-requests or --max-duration of the scan",
    "robots-unavailable": "robots.txt could not be read, so no page beyond the home page was requested",
}
CRAWL_SKIP_TEXT = {
    "other-origin": "other origin",
    "not-followable": "not a web page link",
    "excluded": "excluded",
    "robots-disallowed": "disallowed by robots.txt",
    "query-variants": "too many query variants of one path",
    "beyond-depth": "beyond --crawl-depth",
    "queue-full": "too many links found",
    "fetch-failed": "request failed",
}


def crawl_message(crawl: dict) -> str:
    """One sentence on what a crawl covered and why it stopped (console, HTML report and web UI)."""
    return f"{crawl['pages_visited']} page(s) visited: {CRAWL_STOP_TEXT[crawl['stopped_reason']]}"


_REDACTED_FINDING_FIELDS = ("title", "description", "evidence", "url", "instance_key")


def build_report(
    result: ScanResult,
    *,
    show_secrets: bool = False,
    fail_on: str = DEFAULT_FAIL_ON,
    baseline: Baseline | None = None,
    suppressions: Suppressions | None = None,
    secrets: Iterable[str] = (),
) -> dict:
    """The report dict (SRS 6.2) every output format is rendered from.

    Secrets are redacted unless ``show_secrets`` is true (D2). Only the CLI may pass
    ``show_secrets=True`` (``--show-secrets``); the Web UI never does.

    ``baseline`` (FR-CI-02) and ``suppressions`` (FR-MODEL-06) decide which findings count
    toward the gate; ``summary`` still counts every finding, so its meaning never changes.

    ``secrets`` are the operator's own credentials (``--header``/``--cookie``/proxy password,
    FR-CI-07). They are masked everywhere in the report, even with ``show_secrets``: they are
    never needed in a report, and a target can echo them back in a header or a page.
    """
    report = result.to_dict()
    report["disclaimer"] = SCOPE_NOTE  # FR-RPT-08: scope & limitations, in the JSON report too
    report["secrets_redacted"] = not show_secrets

    # Why the findings may not be the whole picture: the home page could not be fetched, or a
    # traffic limit stopped the scan part way through (FR-AUTHZ-05).
    stopped_by = result.limits.get("stopped_by")
    incomplete_reason = "home-page" if not result.baseline_fetched else stopped_by
    report["gate"] = {"fail_on": fail_on, "incomplete": incomplete_reason is not None}

    if suppressions is not None:
        suppressions.apply(report)
    else:
        for finding in report["findings"]:
            finding["suppression"] = None
    report["baseline"] = compare(report, baseline)
    if baseline is not None and baseline.predates_fingerprint_fix:
        report["errors"].append(
            f"The baseline was written by scanner {baseline.scanner_version or 'of unknown version'}; "
            "1.15.0 changed the fingerprints of CORS and HTTP-redirect findings for scans that did not "
            "start at the site root, so those may show as new. Regenerate the baseline with --json."
        )

    counted = _counts(
        report["findings"],
        [
            i
            for i, f in enumerate(report["findings"])
            if f["suppression"] is None and f["baseline_state"] != "unchanged"
        ],
    )
    report["gate"] = {
        "fail_on": fail_on,
        "failed": any(counted[sev] for sev in FAIL_ON_SEVERITIES[fail_on]),
        "incomplete": incomplete_reason is not None,
        "incomplete_reason": incomplete_reason,
        # "all": every finding counts; "new": only findings absent from the --baseline.
        # Suppressed findings never count, in either case.
        "basis": "all" if baseline is None else "new",
        "counted": counted,
    }
    # FR-SPEC-05: every text taken from the spec is redacted too (a server URL can carry credentials).
    report["api"] = result.api.to_dict(None if show_secrets else redact) if result.api is not None else None
    # FR-CRAWL-01: settings and counts only; no URL of a crawled page is in this object.
    report["crawl"] = result.crawl.to_dict() if result.crawl is not None else None
    # FR-REPORT-10: the pages fetched; their URLs come from the scanned site, so they are redacted.
    report["pages"] = [
        {
            "url": page.url if show_secrets else redact(page.url),
            "status": page.status,
            "depth": page.depth,
            "checked": page.checked,
            "findings": page.findings,
        }
        for page in result.pages[: models.MAX_REPORT_PAGES]
    ]
    if show_secrets:
        return _scrub(report, tuple(secrets))

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
        finding["affected_urls"] = [redact(url, pairs) for url in finding["affected_urls"]]
    return _scrub(report, tuple(secrets))


def _scrub(value, secrets: tuple[str, ...]):
    """Replace every occurrence of each secret, anywhere in the report (strings in dicts and lists)."""
    if not secrets:
        return value
    if isinstance(value, str):
        for secret in secrets:  # longest first (request_options.secrets_of), so no partial overlap
            value = value.replace(secret, f"<redacted len={len(secret)}>")
        return value
    if isinstance(value, list):
        return [_scrub(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _scrub(item, secrets) for key, item in value.items()}
    return value


def scrub_text(text: str, secrets: Iterable[str]) -> str:
    """The same masking for a line that is not part of a report (the --verbose request log)."""
    return _scrub(redact(text), tuple(secrets))


def gate_failed(report: dict, fail_on: str = DEFAULT_FAIL_ON) -> bool:
    """True when a finding that counts is at or above ``fail_on`` (CLI exit code 1, Web UI ``gate_failed``).

    What counts is ``gate.counted`` once ``build_report()`` has set it (suppressed findings and,
    with a baseline, unchanged ones are left out); a bare dict with only ``summary`` counts all.
    """
    counts = (report.get("gate") or {}).get("counted") or report["summary"]
    return any(counts.get(sev, 0) for sev in FAIL_ON_SEVERITIES[fail_on])


def gate_message(gate: dict) -> tuple[str, str]:
    """``(status, text)`` shown for a report's ``gate`` by the HTML report and the Web UI.

    ``status`` is ``"fail"``, ``"warn"`` (scan incomplete) or ``"pass"``; the text names the
    threshold and the CLI exit code, so both views say the same thing.
    """
    threshold = f"--fail-on {gate['fail_on']}"
    new = gate.get("basis") == "new"  # a --baseline is in use: only new findings count
    if gate["failed"]:
        what = "New findings" if new else "Findings"
        return "fail", f"{what} at or above the {threshold} threshold: the CLI exits with code 1 (fails the CI gate)."
    if gate["incomplete"]:
        code = "0 (--fail-on none)" if gate["fail_on"] == "none" else "3"
        reason = gate.get("incomplete_reason")
        if reason in ("max-requests", "max-duration"):
            # Not the home page: a limit the operator set stopped the scan (FR-AUTHZ-05).
            why = f"The scan was stopped early by --{reason}, so some checks did not run."
        else:
            why = "The target home page could not be fetched, so most checks did not run."
        return "warn", f"{why} The CLI exits with code {code}. See the errors below."
    if gate["fail_on"] == "none":
        return "pass", "--fail-on none: the gate never fails; the CLI exits with code 0."
    what = "No new findings" if new else "No findings"
    return "pass", f"{what} at or above the {threshold} threshold: the CLI exits with code 0."


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
