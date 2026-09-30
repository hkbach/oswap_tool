"""Standalone HTML rendering of a scan report.

Takes the same dict as the JSON report (SRS section 6.2, ``ScanResult.to_dict()``)
and returns one self-contained HTML document: inline CSS, no scripts, no external
resources, so it can be opened offline, archived or attached to a ticket.
Every value that came from the scanned site is HTML-escaped.
"""

from __future__ import annotations

from html import escape

from . import __version__

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

_CSS = """
:root { --text:#1c2127; --muted:#5c6670; --border:#dde1e6; --bg:#f6f7f9; --surface:#fff;
  --critical:#b3151b; --high:#d9480f; --medium:#a86400; --low:#1f6fbf; --info:#5c6670;
  --pass-bg:#e7f5ec; --pass:#1b6e3a; --fail-bg:#fdecec; --fail:#a51d1d; --warn-bg:#fff4e0; --warn:#8a5300; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text);
  font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:960px; margin:0 auto; padding:32px 16px 48px; }
h1 { margin:0 0 4px; font-size:24px; } h2 { font-size:18px; margin:28px 0 12px; }
.muted { color:var(--muted); } .target { font-size:16px; font-weight:600; overflow-wrap:anywhere; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:10px;
  padding:16px 20px; margin-bottom:12px; }
table.meta { border-collapse:collapse; }
table.meta th { text-align:left; color:var(--muted); font-weight:500; padding:2px 16px 2px 0; vertical-align:top; }
table.meta td { padding:2px 0; overflow-wrap:anywhere; }
.gate { padding:10px 12px; border-radius:8px; font-weight:600; margin:14px 0; }
.gate.pass { background:var(--pass-bg); color:var(--pass); }
.gate.fail { background:var(--fail-bg); color:var(--fail); }
.gate.warn { background:var(--warn-bg); color:var(--warn); }
table.summary { width:100%; border-collapse:separate; border-spacing:8px 0; table-layout:fixed; margin:0 -8px; }
table.summary td { border:1px solid var(--border); border-top:4px solid var(--c); border-radius:8px;
  text-align:center; padding:8px 4px; }
table.summary .n { display:block; font-size:22px; font-weight:700; color:var(--c); }
table.summary .l { font-size:11px; color:var(--muted); }
.finding { border-left:4px solid var(--c); }
.badge { display:inline-block; font-size:11px; font-weight:700; padding:1px 8px; border-radius:999px;
  color:var(--c); border:1px solid var(--c); margin-right:8px; }
.finding h3 { display:inline; font-size:15px; margin:0; }
.finding p { margin:6px 0 0; }
dl { margin:10px 0 0; display:grid; grid-template-columns:130px 1fr; gap:4px 8px; }
dt { color:var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
code { font:12.5px/1.45 ui-monospace,"Cascadia Mono",Consolas,monospace; background:var(--bg);
  border:1px solid var(--border); border-radius:6px; padding:1px 6px; white-space:pre-wrap; word-break:break-word; }
ul.errors { margin:0; padding-left:20px; overflow-wrap:anywhere; }
footer { margin-top:32px; font-size:12px; color:var(--muted); }
.sev-CRITICAL { --c:var(--critical); } .sev-HIGH { --c:var(--high); } .sev-MEDIUM { --c:var(--medium); }
.sev-LOW { --c:var(--low); } .sev-INFO { --c:var(--info); }
@media print { body { background:#fff; } .card { break-inside:avoid; } }
"""


def _e(value) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _gate(report: dict) -> tuple[str, str]:
    counts = report.get("summary", {})
    if counts.get("CRITICAL") or counts.get("HIGH"):
        return "fail", "CRITICAL/HIGH findings present: the CLI exits with code 1 (fails the CI gate)."
    if any(str(e).startswith("Could not fetch") for e in report.get("errors", [])):
        return "warn", "The target home page could not be fetched, so most checks did not run. See the errors below."
    return "pass", "No CRITICAL/HIGH findings: the CLI exits with code 0."


def _finding(f: dict) -> str:
    sev = f.get("severity", "INFO")
    sev_class = sev if sev in _SEVERITIES else "INFO"
    rows = []
    if f.get("evidence"):
        rows.append(f"<dt>Evidence</dt><dd><code>{_e(f['evidence'])}</code></dd>")
    if f.get("recommendation"):
        rows.append(f"<dt>Recommendation</dt><dd>{_e(f['recommendation'])}</dd>")
    if f.get("url"):
        rows.append(f"<dt>URL</dt><dd><code>{_e(f['url'])}</code></dd>")
    details = f"<dl>{''.join(rows)}</dl>" if rows else ""
    return (
        f'<section class="card finding sev-{sev_class}">'
        f'<span class="badge">{_e(sev)}</span><h3>{_e(f.get("title"))}</h3>'
        f'<p class="muted">{_e(f.get("owasp_category"))} &middot; {_e(f.get("id"))}</p>'
        f"<p>{_e(f.get('description'))}</p>{details}</section>"
    )


def render_html(report: dict) -> str:
    """Render a ScanResult.to_dict()-shaped report as a standalone HTML document."""
    counts = report.get("summary", {})
    rank = {sev: i for i, sev in enumerate(_SEVERITIES)}
    findings = sorted(report.get("findings", []), key=lambda f: rank.get(f.get("severity"), len(rank)))
    gate_class, gate_text = _gate(report)

    summary_cells = "".join(
        f'<td class="sev-{sev}"><span class="n">{int(counts.get(sev, 0))}</span><span class="l">{sev}</span></td>'
        for sev in _SEVERITIES
    )
    errors = report.get("errors", [])
    errors_html = (
        '<h2>Non-fatal errors during scan</h2><div class="card"><ul class="errors">'
        + "".join(f"<li>{_e(err)}</li>" for err in errors)
        + "</ul></div>"
        if errors
        else ""
    )
    findings_html = "".join(_finding(f) for f in findings) or '<p class="muted">No findings.</p>'
    checks = ", ".join(report.get("checks_run", [])) or "None"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OWASP scan report - {_e(report.get("target"))}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>OWASP Passive Scan Report</h1>
<p class="target">{_e(report.get("target"))}</p>
<div class="card">
<table class="meta">
<tr><th>Started (UTC)</th><td>{_e(report.get("started_at"))}</td></tr>
<tr><th>Finished (UTC)</th><td>{_e(report.get("finished_at"))}</td></tr>
<tr><th>Checks run</th><td>{_e(checks)}</td></tr>
<tr><th>Total findings</th><td>{len(findings)}</td></tr>
</table>
<p class="gate {gate_class}">{_e(gate_text)}</p>
<table class="summary"><tr>{summary_cells}</tr></table>
</div>
{errors_html}
<h2>Findings</h2>
{findings_html}
<footer>
Generated by OWASP-Aligned Passive Web Security Scanner {_e(__version__)}.
This is a passive configuration check, not a full DAST assessment: it does not detect real
SQL injection/XSS, business-logic flaws or application-level authentication issues.
Only scan systems you own or are explicitly authorized to test.
</footer>
</main>
</body>
</html>
"""
