"""Shared data models for scan findings."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum

from . import __version__

# Version of the JSON report layout (docs/report.schema.json). Bump on any change to the
# report shape: minor for added fields, major for removed/renamed fields or changed meaning.
# History: "1.0" = unversioned layout of scanner v1.1.0; 1.1 = scanner 1.2.0;
# 1.2 adds final_url and redirect_chain; 1.3 adds gate.
SCHEMA_VERSION = "1.4"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """0 for CRITICAL ... 4 for INFO: the order in which the members are declared."""
        return SEVERITY_ORDER.index(self.value)


# Most severe first. The single definition of the order used by every output format.
SEVERITY_ORDER: tuple[str, ...] = tuple(s.value for s in Severity)


@dataclass
class Finding:
    """A single scan result item."""

    id: str  # short stable code, e.g. "HDR-CSP-MISSING"
    title: str
    severity: Severity
    owasp_category: str  # e.g. "A05:2021 - Security Misconfiguration"
    description: str
    evidence: str = ""
    recommendation: str = ""
    url: str = ""
    # Where on the target this finding applies (header name, cookie name, path, host:port...).
    # Set by the check; together with id and the target origin it forms the fingerprint.
    instance_key: str = ""
    # Filled from catalog.FINDING_CATALOG by catalog.enrich(); a check may set cwe itself.
    cwe: str = ""  # e.g. "CWE-693"; empty for informational findings that are not weaknesses
    confidence: str = ""  # "high" | "medium" | "low"
    references: list[str] = field(default_factory=list)
    fingerprint: str = ""  # stable across scans, see catalog.fingerprint()
    check: str = ""  # name of the check that produced it (a checks_run entry), set by run_scan()
    # Exact (raw, masked) substrings that output.build_report() replaces unless --show-secrets.
    # Internal only: never serialized, never shown (FR-AUTH-02).
    redactions: list[tuple[str, str]] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "owasp_category": self.owasp_category,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "url": self.url,
            "references": list(self.references),
            "instance_key": self.instance_key,
            "fingerprint": self.fingerprint,
            "check": self.check,
        }


@dataclass
class ScanResult:
    """Aggregated result for one target."""

    target: str
    started_at: str
    finished_at: str = ""
    # Where the baseline GET ended after in-scope redirects, and the hops before it (FR-FIX-10).
    final_url: str = ""
    redirect_chain: list = field(default_factory=list)  # [{"url": str, "status": int}, ...]
    findings: list = field(default_factory=list)
    checks_run: list = field(default_factory=list)
    # Check groups selected for this scan (catalog.GROUP_IDS order); groups not listed were not tested.
    scan_groups: list = field(default_factory=lambda: _all_groups())
    errors: list = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scanner_version: str = __version__
    # Version of the rule set in websec_scanner/rules/ that produced this result.
    rules_version: str = field(default_factory=lambda: _rules_version())
    # True once the baseline GET succeeded; False means the scan is incomplete (exit code 3).
    baseline_fetched: bool = False

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary_counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "scanner_version": self.scanner_version,
            "rules_version": self.rules_version,
            "scan_id": self.scan_id,
            "target": self.target,
            "final_url": self.final_url,
            "redirect_chain": [dict(hop) for hop in self.redirect_chain],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scan_groups": list(self.scan_groups),
            "checks_run": self.checks_run,
            "summary": self.summary_counts(),
            # Severity first (FR-REPORT-02); id and instance_key make the order deterministic,
            # since some checks collect findings from parallel requests.
            "findings": [
                f.to_dict() for f in sorted(self.findings, key=lambda x: (x.severity.rank, x.id, x.instance_key))
            ],
            "errors": self.errors,
        }


def _all_groups() -> list[str]:
    from .catalog import GROUP_IDS  # catalog imports this module

    return list(GROUP_IDS)


def _rules_version() -> str:
    from .rule_loader import rules_version  # late import: rule_loader imports this module

    return rules_version()
