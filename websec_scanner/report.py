"""CLI rendering and JSON export of a report dict built by output.build_report()."""

from __future__ import annotations

import json
import textwrap

from .catalog import CHECK_GROUPS
from .models import SEVERITY_ORDER
from .output import SCOPE_NOTE

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
    print("-" * 72)

    if not report["findings"]:
        print(" No findings.")
    else:
        for f in report["findings"]:  # already sorted by build_report()
            tag = _colorize(f"[{f['severity']}]", f["severity"], use_color)
            print(f" {tag} {f['title']}")
            confidence = f"confidence: {f['confidence']}" if f["confidence"] else ""
            classification = " | ".join(filter(None, (f["cwe"], confidence)))
            print(f"     OWASP: {f['owasp_category']}" + (f" | {classification}" if classification else ""))
            print(f"     {f['description']}")
            if f["evidence"]:
                print(f"     Evidence: {f['evidence']}")
            if f["recommendation"]:
                print(f"     Fix: {f['recommendation']}")
            if f["url"]:
                print(f"     URL: {f['url']}")
            print()

    if report["errors"]:
        print("-" * 72)
        print(" Non-fatal errors during scan:")
        for e in report["errors"]:
            print(f"  - {e}")

    print("=" * 72)
    print(textwrap.fill(SCOPE_NOTE, width=72, initial_indent=" ", subsequent_indent=" "))


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
