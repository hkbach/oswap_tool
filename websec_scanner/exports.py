"""CSV and JUnit XML exports (FR-RPT-03).

Both take the report dict of ``output.build_report()``, so they carry exactly what the
JSON report carries, already redacted. Every value that came from the scanned site is
treated as hostile: CSV cells are defused against spreadsheet formulas, and JUnit text is
escaped by ElementTree with characters XML 1.0 cannot hold removed.
"""

from __future__ import annotations

import csv
import io
import re
import xml.etree.ElementTree as ET

from .catalog import group_of_check
from .output import FAIL_ON_SEVERITIES, gate_message

_CSV_COLUMNS = (
    "severity",
    "id",
    "title",
    "url",
    "affected_count",
    "instance_key",
    "cwe",
    "cvss_score",
    "confidence",
    "baseline_state",
    "suppressed",
    "counts_toward_gate",
    "description",
    "recommendation",
    "fingerprint",
)
# OWASP "CSV Injection": a cell starting with one of these runs as a formula in Excel,
# LibreOffice or Google Sheets. Tab and CR are included because some apps strip them first.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
# Everything XML 1.0 allows; anything else (e.g. NUL in a header value) makes the file unreadable.
_XML_INVALID = re.compile("[^\u0009\u000a\u000d -퟿-�\U00010000-\U0010ffff]")


def _counts_toward_gate(finding: dict) -> bool:
    return finding.get("suppression") is None and finding.get("baseline_state") != "unchanged"


def _defuse(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def to_csv(report: dict) -> str:
    """One row per finding, in report order (FR-REPORT-02)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for f in report["findings"]:
        writer.writerow(
            {
                **{column: _defuse(f.get(column)) for column in _CSV_COLUMNS},
                "cvss_score": "" if f.get("cvss_score") is None else f["cvss_score"],
                "baseline_state": f.get("baseline_state") or "",
                "suppressed": _defuse((f.get("suppression") or {}).get("reason", "")),
                "counts_toward_gate": "yes" if _counts_toward_gate(f) else "no",
            }
        )
    return buffer.getvalue()


def _xml(value: object) -> str:
    return _XML_INVALID.sub("", "" if value is None else str(value))


def to_junit(report: dict) -> str:
    """One test case per finding, plus one for the scan itself.

    A finding that fails the gate is a ``<failure>``; every other finding is ``<skipped>``
    with the reason (below the threshold, unchanged since the baseline, suppressed). The
    scan's own test case fails when the scan was incomplete. So the file has failures
    exactly when the CLI exits non-zero, and a CI dashboard reaches the same verdict.
    """
    gate = report["gate"]
    threshold = set(FAIL_ON_SEVERITIES[gate["fail_on"]])
    cases: list[ET.Element] = []

    for f in report["findings"]:
        case = ET.Element(
            "testcase",
            classname=_xml(f"websec-scanner.{group_of_check(f['check']) if f.get('check') else 'scan'}"),
            name=_xml(f"{f['id']} {f.get('instance_key', '')}".strip()),
        )
        others = f.get("affected_count", 1) - 1
        also = (
            f"Also seen on {others} other page(s): " + ", ".join(u for u in f["affected_urls"] if u != f["url"])
            if others > 0
            else ""
        )
        detail = "\n".join(
            part
            for part in (f.get("description"), f.get("evidence"), f.get("recommendation"), f.get("url"), also)
            if part
        )
        if f.get("suppression"):
            reason = f"suppressed until {f['suppression']['expires']}: {f['suppression']['reason']}"
            ET.SubElement(case, "skipped", message=_xml(reason))
        elif f.get("baseline_state") == "unchanged":
            ET.SubElement(case, "skipped", message="unchanged since the baseline")
        elif f["severity"] in threshold:
            failure = ET.SubElement(case, "failure", message=_xml(f"{f['severity']}: {f['title']}"), type=f["severity"])
            failure.text = _xml(detail)
        else:
            ET.SubElement(
                case, "skipped", message=_xml(f"{f['severity']} is below the --fail-on {gate['fail_on']} threshold")
            )
        cases.append(case)

    # The scan itself, so a clean scan is still one passing test and an incomplete one fails.
    scan = ET.Element("testcase", classname="websec-scanner.scan", name=_xml(f"scan {report['target']}"))
    if gate["incomplete"] and gate["fail_on"] != "none":
        failure = ET.SubElement(scan, "failure", message=_xml(gate_message(gate)[1]), type="incomplete")
        failure.text = _xml("\n".join(report.get("errors") or []))
    cases.append(scan)

    failures = sum(1 for c in cases if c.find("failure") is not None)
    skipped = sum(1 for c in cases if c.find("skipped") is not None)
    attrs = {"tests": str(len(cases)), "failures": str(failures), "skipped": str(skipped), "errors": "0"}
    root = ET.Element("testsuites", name="websec-scanner", **attrs)
    suite = ET.SubElement(
        root,
        "testsuite",
        name=_xml(f"websec-scanner {report['target']}"),
        timestamp=_xml(report.get("started_at")),
        **attrs,
    )
    suite.extend(cases)
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"
