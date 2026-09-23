from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    owasp: str = ""


@dataclass(frozen=True)
class CheckError:
    check_id: str
    message: str


@dataclass
class ScanResult:
    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[CheckError] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["started_at"] = self.started_at.isoformat()
        data["finished_at"] = self.finished_at.isoformat() if self.finished_at else None
        return data
