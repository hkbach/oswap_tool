"""Compare a scan with a previous one (FR-CI-02, FR-RPT-06).

A baseline is simply the ``--json`` report of an earlier scan. Findings are matched on
``fingerprint``, which is stable across scans of the same site (SRS 6.1, FR-MODEL-07).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .redact import redact

_FINGERPRINT = re.compile(r"^[0-9a-f]{32}$")
# FR-MODEL-07 (scanner 1.15.0) changed the fingerprints of CORS and HTTP-redirect findings for
# scans that did not start at the site root. A baseline from before that may show those as new.
_FINGERPRINTS_CHANGED_IN = (1, 15, 0)
_KEPT_FIELDS = ("id", "title", "severity", "url", "fingerprint", "check")


class BaselineError(ValueError):
    """The baseline file cannot be used; the message says why."""


@dataclass(frozen=True)
class Baseline:
    source: str
    scan_id: str | None
    started_at: str | None
    scanner_version: str | None
    findings: tuple[dict, ...]

    @property
    def fingerprints(self) -> frozenset[str]:
        return frozenset(f["fingerprint"] for f in self.findings)

    @property
    def predates_fingerprint_fix(self) -> bool:
        return _version_tuple(self.scanner_version) < _FINGERPRINTS_CHANGED_IN


def load_baseline(path: str) -> Baseline:
    """Read a previous ``--json`` report. Raises ``BaselineError`` with a clear message."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path!r}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise BaselineError(f"baseline {path!r} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise BaselineError(f"baseline {path!r} is not a scan report (write one with --json)")

    findings = []
    for index, finding in enumerate(data["findings"]):
        fingerprint = finding.get("fingerprint") if isinstance(finding, dict) else None
        if not isinstance(fingerprint, str) or not _FINGERPRINT.match(fingerprint):
            raise BaselineError(
                f"baseline {path!r}: finding {index} has no fingerprint; it was written by a scanner "
                "older than 1.2.0, so write a new baseline with --json"
            )
        # Keep only what a comparison shows, and redact it: a baseline written with
        # --show-secrets may carry raw values that must not reach the new report.
        findings.append({key: redact(str(finding.get(key) or "")) for key in _KEPT_FIELDS})

    return Baseline(
        source=path,
        scan_id=data.get("scan_id") if isinstance(data.get("scan_id"), str) else None,
        started_at=data.get("started_at") if isinstance(data.get("started_at"), str) else None,
        scanner_version=data.get("scanner_version") if isinstance(data.get("scanner_version"), str) else None,
        findings=tuple(findings),
    )


def compare(report: dict, baseline: Baseline | None) -> dict | None:
    """Mark each finding of ``report`` as new or unchanged; return the ``baseline`` block.

    A baseline finding that is missing now is only called **fixed** when its check ran in
    this scan and the scan finished. Otherwise nobody looked again (``--checks`` left the group
    out, or a limit stopped the scan), and it is reported as **not rechecked** instead.
    """
    if baseline is None:
        for finding in report["findings"]:
            finding["baseline_state"] = None
        return None

    known = baseline.fingerprints
    current = {f["fingerprint"] for f in report["findings"]}
    for finding in report["findings"]:
        finding["baseline_state"] = "unchanged" if finding["fingerprint"] in known else "new"

    ran = set(report["checks_run"])
    finished = report["gate"]["incomplete"] is False
    fixed, not_rechecked, seen = [], [], set()
    for old in baseline.findings:
        if old["fingerprint"] in current or old["fingerprint"] in seen:
            continue  # still present, or a duplicate fingerprint already handled
        seen.add(old["fingerprint"])
        (fixed if finished and old["check"] in ran else not_rechecked).append(old)

    states = [f["baseline_state"] for f in report["findings"]]
    return {
        "source": baseline.source,
        "scan_id": baseline.scan_id,
        "started_at": baseline.started_at,
        "fixed": fixed,
        "not_rechecked": not_rechecked,
        "counts": {
            "new": states.count("new"),
            "unchanged": states.count("unchanged"),
            "fixed": len(fixed),
            "not_rechecked": len(not_rechecked),
        },
    }


def _version_tuple(version: str | None) -> tuple[int, ...]:
    """``"1.13.0"`` -> ``(1, 13, 0)``; anything unparseable sorts as oldest."""
    try:
        return tuple(int(part) for part in (version or "").split(".")[:3])
    except ValueError:
        return (0,)
