from collections.abc import Iterable
from datetime import UTC, datetime

import httpx

from owasp_tool.checks.base import Check
from owasp_tool.models import CheckError, ScanResult


def run_scan(target: str, checks: Iterable[Check], client: httpx.Client) -> ScanResult:
    result = ScanResult(target=target)
    for check in checks:
        try:
            result.findings.extend(check.run(client, target))
        except Exception as exc:  # one failing check must not abort the whole scan
            result.errors.append(CheckError(check_id=check.id, message=str(exc)))
    result.findings.sort(key=lambda f: f.severity.rank, reverse=True)
    result.finished_at = datetime.now(UTC)
    return result
