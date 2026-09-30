"""CLI rendering and JSON export for scan results."""
from __future__ import annotations

import json

from .models import ScanResult, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[41m\033[97m",  # white on red
    Severity.HIGH: "\033[91m",  # red
    Severity.MEDIUM: "\033[93m",  # yellow
    Severity.LOW: "\033[94m",  # blue
    Severity.INFO: "\033[90m",  # gray
}
_RESET = "\033[0m"


def _colorize(text: str, severity: Severity, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_SEVERITY_COLOR[severity]}{text}{_RESET}"


def print_report(result: ScanResult, use_color: bool = True) -> None:
    counts = result.summary_counts()
    print("=" * 72)
    print(f" OWASP-aligned scan report for: {result.target}")
    print(f" Started:  {result.started_at}")
    print(f" Finished: {result.finished_at}")
    print(f" Checks run: {', '.join(result.checks_run)}")
    print("=" * 72)
    print(
        " Summary: "
        + " | ".join(f"{sev}: {counts[sev]}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    )
    print("-" * 72)

    if not result.findings:
        print(" No findings.")
    else:
        for f in sorted(result.findings, key=lambda x: x.severity.rank):
            tag = _colorize(f"[{f.severity.value}]", f.severity, use_color)
            print(f" {tag} {f.title}")
            print(f"     OWASP: {f.owasp_category}")
            print(f"     {f.description}")
            if f.evidence:
                print(f"     Evidence: {f.evidence}")
            if f.recommendation:
                print(f"     Fix: {f.recommendation}")
            if f.url:
                print(f"     URL: {f.url}")
            print()

    if result.errors:
        print("-" * 72)
        print(" Non-fatal errors during scan:")
        for e in result.errors:
            print(f"  - {e}")

    print("=" * 72)


def write_json(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
