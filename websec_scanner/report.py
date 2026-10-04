"""CLI rendering and JSON export of a report dict built by output.build_report()."""

from __future__ import annotations

import json
import re
import textwrap

from .catalog import CHECK_GROUPS
from .models import SEVERITY_ORDER
from .output import CRAWL_SKIP_TEXT, CVSS_NOTE, SCOPE_NOTE, crawl_message

_SEVERITIES = SEVERITY_ORDER
# Everything a terminal acts on: C0 controls except tab, DEL, and the C1 range (which includes
# the 8-bit CSI introducer \x9b). The scanner quotes headers and bodies from the scanned site,
# so without this a target could send an escape sequence that erases the findings just printed
# and writes its own verdict instead: the thing being measured would control the measurement.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def printable_text(value: object) -> str:
    """Target-derived text, safe to print: control characters become visible ``\\xNN`` escapes.

    Shown rather than dropped, so a target cannot hide part of a value it controls.
    """
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", str(value))


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
    print(f" Non-intrusive scan report for: {printable_text(report['target'])}")
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
            print(f" {tag} {printable_text(f['title'])}{_state_tag(f)}")
            confidence = f"confidence: {f['confidence']}" if f["confidence"] else ""
            cvss_text = f"CVSS 3.1 base: {f['cvss_score']} (estimated)" if f.get("cvss_vector") else ""
            classification = " | ".join(filter(None, (f["cwe"], confidence, cvss_text)))
            owasp = printable_text(f["owasp_category"])
            print(f"     OWASP: {owasp}" + (f" | {classification}" if classification else ""))
            print(f"     {printable_text(f['description'])}")
            if f["evidence"]:
                print(f"     Evidence: {printable_text(f['evidence'])}")
            if f["recommendation"]:
                print(f"     Fix: {printable_text(f['recommendation'])}")
            if f["url"]:
                print(f"     URL: {printable_text(f['url'])}")
            if f["affected_count"] > 1:
                print(f"     Seen on {f['affected_count']} pages: {_other_pages(f)}")
            print()

    if report.get("baseline"):
        _print_comparison(report["baseline"])

    if report.get("crawl"):
        _print_crawl(report["crawl"])

    if report.get("api"):
        _print_api(report["api"])

    if report["errors"]:
        print("-" * 72)
        print(" Non-fatal errors during scan:")
        for e in report["errors"]:
            print(f"  - {printable_text(e)}")

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
        tags.append(f"[SUPPRESSED until {printable_text(s['expires'])}: {printable_text(s['reason'])}]")
    return (" " + " ".join(tags)) if tags else ""


_API_LINES = 100  # endpoints shown on the console; the JSON report has every one


def _other_pages(finding: dict) -> str:
    """The pages after the finding's own URL, as many as the report lists, and how many more there were."""
    others = [url for url in finding["affected_urls"] if url != finding["url"]]
    text = ", ".join(printable_text(url) for url in others[:5])
    left = finding["affected_count"] - 1 - min(len(others), 5)
    return f"{text}" + (f" and {left} other page(s)" if left > 0 else "")


def _print_crawl(crawl: dict) -> None:
    """FR-CRAWL-01: what the crawl covered and why it stopped."""
    print("-" * 72)
    print(f" Crawl: {crawl_message(crawl)}")
    robots = "followed" if crawl["respect_robots"] else "ignored (--ignore-robots)"
    print(
        f"   Limits: depth {crawl['max_depth']}, {crawl['max_pages']} pages, {crawl['max_duration']:g} s; "
        f"robots.txt {robots}"
    )
    if crawl["skipped"]:
        parts = ", ".join(
            f"{count} {CRAWL_SKIP_TEXT.get(reason, reason)}" for reason, count in crawl["skipped"].items()
        )
        print(f"   Links not followed: {parts}")


def _print_api(api: dict) -> None:
    """FR-SPEC-05: the inventory read from --api-spec. Every text in it came from a file, so none is trusted."""
    print("-" * 72)
    print(
        f" API inventory: {printable_text(api['title'])} "
        f"({api['format']} {printable_text(api['version'])}, from {printable_text(api['source'])})"
    )
    print("   Read from the spec file only: no request was sent to any endpoint or server it names.")
    if api["servers"]:
        print("   Servers: " + ", ".join(printable_text(s) for s in api["servers"]))
    if api["security_schemes"]:
        schemes = (
            f"{printable_text(s['name'])} ({s['type']}, {printable_text(s['detail'])})"
            if s["detail"]
            else f"{printable_text(s['name'])} ({printable_text(s['type'])})"
            for s in api["security_schemes"]
        )
        print("   Security schemes: " + ", ".join(schemes))
    print(f"   {api['endpoint_count']} endpoint(s):")
    for endpoint in api["endpoints"][:_API_LINES]:
        line = f"     {endpoint['method']:<7} {printable_text(endpoint['path'])}"
        if endpoint["parameters"]:
            line += "  params: " + ", ".join(f"{printable_text(p['name'])} ({p['in']})" for p in endpoint["parameters"])
        if endpoint["security"]:
            line += "  auth: " + ", ".join(printable_text(name) for name in endpoint["security"])
        if endpoint["deprecated"]:
            line += "  [deprecated]"
        print(line)
    if api["endpoint_count"] > _API_LINES:
        print(f"     ... and {api['endpoint_count'] - _API_LINES} more (all of them are in the JSON report)")


def _print_comparison(baseline: dict) -> None:
    """FR-RPT-06: new / fixed / still present since the baseline."""
    counts = baseline["counts"]
    print("-" * 72)
    since = baseline.get("started_at") or "unknown time"
    print(f" Compared with baseline from {printable_text(since)} ({printable_text(baseline['source'])}):")
    print(
        f"   new: {counts['new']} | unchanged: {counts['unchanged']} | fixed: {counts['fixed']}"
        f" | not rechecked: {counts['not_rechecked']}"
    )
    if baseline["fixed"]:
        print(" Fixed since the baseline:")
        for f in baseline["fixed"]:
            print(f"  - [{f['severity']}] {printable_text(f['title'])}")
    if baseline["not_rechecked"]:
        print(" Not rechecked (its check did not run, or the scan did not finish), so not counted as fixed:")
        for f in baseline["not_rechecked"]:
            print(f"  - [{f['severity']}] {printable_text(f['title'])}")


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
