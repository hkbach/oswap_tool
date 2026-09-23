from owasp_tool.models import ScanResult


def render(result: ScanResult) -> str:
    lines = [f"Target: {result.target}", f"Findings: {len(result.findings)}", ""]
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}] {f.title} ({f.check_id})")
        if f.owasp:
            lines.append(f"  OWASP: {f.owasp}")
        lines.append(f"  {f.description}")
        if f.evidence:
            lines.append(f"  Evidence: {f.evidence}")
        if f.recommendation:
            lines.append(f"  Fix: {f.recommendation}")
        lines.append("")
    for e in result.errors:
        lines.append(f"[ERROR] {e.check_id}: {e.message}")
    return "\n".join(lines).rstrip() + "\n"
