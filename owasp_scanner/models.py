"""Shared data models for scan findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order[self]


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

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "owasp_category": self.owasp_category,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "url": self.url,
        }


@dataclass
class ScanResult:
    """Aggregated result for one target."""

    target: str
    started_at: str
    finished_at: str = ""
    findings: list = field(default_factory=list)
    checks_run: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary_counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "checks_run": self.checks_run,
            "summary": self.summary_counts(),
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: x.severity.rank)],
            "errors": self.errors,
        }
