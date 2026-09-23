from collections.abc import Callable

from owasp_tool.models import ScanResult
from owasp_tool.reporting import console, json_report

REPORTERS: dict[str, Callable[[ScanResult], str]] = {
    "console": console.render,
    "json": json_report.render,
}
