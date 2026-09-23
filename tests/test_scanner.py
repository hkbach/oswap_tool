import pytest

from owasp_tool.checks import get_checks
from owasp_tool.checks.base import Check
from owasp_tool.models import Finding, Severity
from owasp_tool.scanner import run_scan


class _StaticCheck(Check):
    id = "static"
    name = "static"
    owasp = ""

    def __init__(self, severities):
        self._severities = severities

    def run(self, client, target):
        return [Finding(self.id, s.value, s, "") for s in self._severities]


class _BrokenCheck(Check):
    id = "broken"
    name = "broken"
    owasp = ""

    def run(self, client, target):
        raise RuntimeError("boom")


def test_findings_sorted_by_severity(mock_client):
    check = _StaticCheck([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM])
    result = run_scan("https://example.test", [check], mock_client())
    assert [f.severity for f in result.findings] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]
    assert result.finished_at is not None


def test_failing_check_is_recorded_not_raised(mock_client):
    result = run_scan("https://example.test", [_BrokenCheck()], mock_client())
    assert result.findings == []
    assert result.errors[0].check_id == "broken"
    assert "boom" in result.errors[0].message


def test_get_checks_rejects_unknown_id():
    with pytest.raises(ValueError, match="nope"):
        get_checks(["nope"])
