import json

from owasp_tool.models import ScanResult


def render(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"
