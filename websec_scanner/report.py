"""CLI rendering and JSON export of a report dict built by output.build_report()."""

from __future__ import annotations

import json
import textwrap

from .catalog import CHECK_GROUPS
from .models import SEVERITY_ORDER
from .output import CVSS_NOTE, SCOPE_NOTE

_SEVERITIES = SEVERITY_ORDER
_SEVERITY_COLOR = {
    "CRITICAL": "\033[41m\033[97m",  # white on red
    "HIGH": "\033[91m",  # red
    "MEDIUM": "\033[93m",  # yellow
    "LOW": "\033[94m",  # blue
    "INFO": "\033[90m",  # gray
}
_RESET = "\033[0m"


def _colorize(text: str, severity: str, use_color: bool) -> str:
    if not use_color or severity not in _SEVERITY_COLOR:
        return text
    return f"{_SEVERITY_COLOR[severity]}{text}{_RESET}"


def print_report(report: dict, use_color: bool = True) -> None:
    counts = report["summary"]
    print("=" * 72)
    print(f" Non-intrusive scan report for: {report['target']}")
    print(f" Started:  {report['started_at']}")
    print(f" Finished: {report['finished_at']}")
    titles = {g.id: g.title for g in CHECK_GROUPS}
    selected = report["scan_groups"]
    print(f" Check groups: {', '.join(titles[g] for g in selected)}")
    skipped = [g.title for g in CHECK_GROUPS if g.id not in selected]
    if skipped:
        print(f" Not selected (not tested): {', '.join(skipped)}")
    print(f" Checks run: {', '.join(report['checks_run'])}")
    print("=" * 72)
    print(" Summary: " + " | ".join(f"{sev}: {counts[sev]}" for sev in _SEVERITIES))
    gate = report["gate"]
    if gate.get("basis") == "new" or any(f.get("suppression") for f in report["findings"]):
        # summary counts every finding; say which of them the gate actually counted.
        counted = gate["counted"]
        print(" Counted toward the gate: " + " | ".join(f"{sev}: {counted[sev]}" for sev in _SEVERITIES))
    print("-" * 72)

    if not report["findings"]:
        print(" No findings.")
    else:
        for f in report["findings"]:  # already sorted by build_report()
            tag = _colorize(f"[{f['severity']}]", f["severity"], use_color)
            print(f" {tag} {f['title']}{_state_tag(f)}")
            confidence = f"confidence: {f['confidence']}" if f["confidence"] else ""
            cvss_text = f"CVSS 3.1 base: {f['cvss_score']} (estimated)" if f.get("cvss_vector") else ""
            classification = " | ".join(filter(None, (f["cwe"], confidence, cvss_text)))
            print(f"     OWASP: {f['owasp_category']}" + (f" | {classification}" if classification else ""))
            print(f"     {f['description']}")
            if f["evidence"]:
                print(f"     Evidence: {f['evidence']}")
            if f["recommendation"]:
                print(f"     Fix: {f['recommendation']}")
            if f["url"]:
                print(f"     URL: {f['url']}")
            print()

    if report.get("baseline"):
        _print_comparison(report["baseline"])

    if report["errors"]:
        print("-" * 72)
        print(" Non-fatal errors during scan:")
        for e in report["errors"]:
            print(f"  - {e}")

    print("=" * 72)
    if any(f.get("cvss_vector") for f in report["findings"]):
        print(textwrap.fill(CVSS_NOTE, width=72, initial_indent=" ", subsequent_indent=" "))
        print()
    print(textwrap.fill(SCOPE_NOTE, width=72, initial_indent=" ", subsequent_indent=" "))


def _state_tag(finding: dict) -> str:
    """Where this finding stands against --baseline and --suppressions (FR-CI-02, FR-MODEL-06)."""
    tags = []
    if finding.get("baseline_state") == "new":
        tags.append("[NEW]")
    elif finding.get("baseline_state") == "unchanged":
        tags.append("[UNCHANGED]")
    if finding.get("suppression"):
        s = finding["suppression"]
        tags.append(f"[SUPPRESSED until {s['expires']}: {s['reason']}]")
    return (" " + " ".join(tags)) if tags else ""


def _print_comparison(baseline: dict) -> None:
    """FR-RPT-06: new / fixed / still present since the baseline."""
    counts = baseline["counts"]
    print("-" * 72)
    since = baseline.get("started_at") or "unknown time"
    print(f" Compared with baseline from {since} ({baseline['source']}):")
    print(
        f"   new: {counts['new']} | unchanged: {counts['unchanged']} | fixed: {counts['fixed']}"
        f" | not rechecked: {counts['not_rechecked']}"
    )
    if baseline["fixed"]:
        print(" Fixed since the baseline:")
        for f in baseline["fixed"]:
            print(f"  - [{f['severity']}] {f['title']}")
    if baseline["not_rechecked"]:
        print(" Not rechecked (its check did not run, or the scan did not finish), so not counted as fixed:")
        for f in baseline["not_rechecked"]:
            print(f"  - [{f['severity']}] {f['title']}")


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
