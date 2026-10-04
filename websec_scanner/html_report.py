"""Standalone HTML rendering of a scan report.

Takes the same dict as the JSON report (SRS section 6.2, ``ScanResult.to_dict()``)
and returns one self-contained HTML document: inline CSS, no scripts, no external
resources, so it can be opened offline, archived or attached to a ticket.
Every value that came from the scanned site is HTML-escaped.
"""

from __future__ import annotations

from html import escape

from . import __version__
from .catalog import CHECK_GROUPS, group_of_check
from .models import SEVERITY_ORDER
from .output import (
    API_LISTED_ENDPOINTS,
    CRAWL_SKIP_TEXT,
    CRAWL_STOP_TEXT,
    CVSS_NOTE,
    SCOPE_NOTE,
    gate_message,
    group_findings,
    owasp_groups,
)
from .report import printable_text

_GROUP_TITLE = {g.id: g.title for g in CHECK_GROUPS}

_SEVERITIES = SEVERITY_ORDER
_STATUS_TEXT = {"clean": "No issues", "not-run": "Not run", "not-selected": "Not selected"}
# Shown in a group without findings (same wording as the web UI).
_STATUS_NOTE = {
    "clean": "Checked; nothing to report.",
    "not-run": "Selected, but it could not run for this target (for example TLS on a plain-HTTP site, "
    "or the home page could not be fetched).",
    "not-selected": "Not selected for this scan: not tested.",
}

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
ol.top-issues { margin:0; padding-left:20px; } ol.top-issues li { margin:4px 0; }
ol.top-issues a { color:inherit; }
footer { margin-top:32px; font-size:12px; color:var(--muted); }
.sev-CRITICAL { --c:var(--critical); } .sev-HIGH { --c:var(--high); } .sev-MEDIUM { --c:var(--medium); }
.sev-LOW { --c:var(--low); } .sev-INFO { --c:var(--info); }
table.groups { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); }
table.groups th, table.groups td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--border);
  vertical-align:top; }
table.groups th { color:var(--muted); font-weight:500; font-size:12px; }
table.groups td.n { text-align:center; width:64px; }
table.groups td.n.zero { color:var(--muted); }
table.groups a { color:inherit; }
.status { display:inline-block; font-size:11px; font-weight:700; padding:1px 8px; border-radius:999px;
  white-space:nowrap; }
.status.issues { background:var(--fail-bg); color:var(--fail); }
.status.clean { background:var(--pass-bg); color:var(--pass); }
.status.not-run { background:var(--warn-bg); color:var(--warn); }
.status.not-selected { background:var(--bg); color:var(--muted); border:1px solid var(--border); }
.state { display:inline-block; font-size:11px; font-weight:700; padding:1px 8px; border-radius:999px; margin-left:8px;
  vertical-align:middle; }
.state.new { background:var(--fail-bg); color:var(--fail); }
.state.unchanged { background:var(--bg); color:var(--muted); border:1px solid var(--border); }
.state.suppressed { background:var(--warn-bg); color:var(--warn); }
table.compare td, table.compare th { padding:4px 14px 4px 0; text-align:left; }
h3.group { font-size:16px; margin:22px 0 4px; } h3.group .status { margin-left:8px; vertical-align:middle; }
p.group-desc { margin:0 0 10px; }
.finding h4 { display:inline; font-size:15px; margin:0; }
.ids a { color:var(--muted); }
table.api { width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }
table.api th, table.api td { text-align:left; padding:4px 8px; border-bottom:1px solid var(--line, #ddd);
  overflow-wrap:anywhere; vertical-align:top; }
@media print { body { background:#fff; } .card { break-inside:avoid; } }
"""


def _e(value) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _state_pills(f: dict) -> str:
    """Where a finding stands against --baseline and --suppressions (FR-CI-02, FR-MODEL-06)."""
    pills = []
    if f.get("baseline_state") in ("new", "unchanged"):
        state = f["baseline_state"]
        pills.append(f'<span class="state {state}">{"New" if state == "new" else "Unchanged"}</span>')
    if f.get("suppression"):
        pills.append('<span class="state suppressed">Suppressed</span>')
    return "".join(pills)


def _comparison(baseline: dict | None) -> str:
    """FR-RPT-06: what is new, unchanged and fixed since the baseline."""
    if not baseline:
        return ""
    counts = baseline["counts"]

    def listing(title: str, items: list[dict]) -> str:
        if not items:
            return ""
        rows = "".join(f"<li>[{_e(f['severity'])}] {_e(f['title'])}</li>" for f in items)
        return f'<p>{_e(title)}</p><ul class="errors">{rows}</ul>'

    since = baseline.get("started_at") or "an unknown time"
    return (
        "<h2>Compared with baseline</h2>"
        f'<div class="card"><p class="muted">Baseline from {_e(since)} ({_e(baseline["source"])}).</p>'
        '<table class="compare"><tr><th>New</th><th>Unchanged</th><th>Fixed</th><th>Not rechecked</th></tr>'
        f"<tr><td>{counts['new']}</td><td>{counts['unchanged']}</td><td>{counts['fixed']}</td>"
        f"<td>{counts['not_rechecked']}</td></tr></table>"
        + listing("Fixed since the baseline:", baseline["fixed"])
        + listing(
            "Not rechecked (their check did not run, or the scan did not finish), so not counted as fixed:",
            baseline["not_rechecked"],
        )
        + "</div>"
    )


def _finding(f: dict, index: int) -> str:
    sev = f.get("severity", "INFO")
    sev_class = sev if sev in _SEVERITIES else "INFO"
    rows = []
    if f.get("evidence"):
        rows.append(f"<dt>Evidence</dt><dd><code>{_e(f['evidence'])}</code></dd>")
    if f.get("recommendation"):
        rows.append(f"<dt>Recommendation</dt><dd>{_e(f['recommendation'])}</dd>")
    if f.get("url"):
        rows.append(f"<dt>URL</dt><dd><code>{_e(f['url'])}</code></dd>")
    if f.get("affected_count", 1) > 1:
        others = [url for url in f["affected_urls"] if url != f["url"]]
        more = f["affected_count"] - 1 - len(others)
        listing = "".join(f"<li><code>{_e(url)}</code></li>" for url in others)
        tail = f"<li>and {more} more page(s)</li>" if more > 0 else ""
        rows.append(f"<dt>Also seen on</dt><dd><ul>{listing}{tail}</ul></dd>")
    if f.get("suppression"):
        s = f["suppression"]
        rows.append(f"<dt>Suppressed</dt><dd>until {_e(s['expires'])}: {_e(s['reason'])}</dd>")
    if f.get("cvss_vector"):
        rows.append(
            f"<dt>CVSS 3.1 base (estimated)</dt><dd>{f['cvss_score']} &middot; <code>{_e(f['cvss_vector'])}</code></dd>"
        )
    group_id = group_of_check(f["check"]) if f.get("check") else ""
    if group_id:
        rows.append(
            f"<dt>Reproduce</dt><dd>Re-run <code>--checks {_e(group_id)}</code> "
            f"({_e(_GROUP_TITLE[group_id])}) against this target, or inspect the response above directly.</dd>"
        )
    links = [ref for ref in f.get("references") or [] if str(ref).startswith("https://")]
    if links:
        items = "<br>".join(f'<a href="{_e(ref)}">{_e(ref)}</a>' for ref in links)
        rows.append(f"<dt>References</dt><dd>{items}</dd>")
    details = f"<dl>{''.join(rows)}</dl>" if rows else ""
    classification = " &middot; ".join(
        _e(part)
        for part in (
            f.get("owasp_category"),
            f.get("cwe"),
            f"confidence {f['confidence']}" if f.get("confidence") else "",
            f.get("id"),
        )
        if part
    )
    return (
        f'<section class="card finding sev-{sev_class}" id="finding-{index}">'
        f'<span class="badge">{_e(sev)}</span><h4>{_e(f.get("title"))}</h4>{_state_pills(f)}'
        f'<p class="muted">{classification}</p>'
        f"<p>{_e(f.get('description'))}</p>{details}</section>"
    )


_TOP_ISSUES_LIMIT = 5


def _top_issues(findings: list[dict]) -> str:
    """Up to the 5 highest-severity findings, most severe first (FR-REPORT-02 order)."""
    if not findings:
        return ""
    rank = {sev: i for i, sev in enumerate(_SEVERITIES)}
    ordered = sorted(
        range(len(findings)), key=lambda i: (rank.get(findings[i].get("severity"), len(rank)), findings[i].get("id"))
    )[:_TOP_ISSUES_LIMIT]
    items = "".join(
        f'<li><span class="badge sev-{findings[i].get("severity", "INFO")}">{_e(findings[i].get("severity"))}</span> '
        f'<a href="#finding-{i}">{_e(findings[i].get("title"))}</a></li>'
        for i in ordered
    )
    return f'<h2>Top issues</h2><div class="card"><ol class="top-issues">{items}</ol></div>'


def _count_cells(counts: dict) -> str:
    return "".join(
        f'<td class="n{"" if counts.get(sev) else " zero"}">{int(counts.get(sev, 0))}</td>' for sev in _SEVERITIES
    )


def _status(status: str, count: int) -> str:
    text = f"{count} issue{'' if count == 1 else 's'}" if status == "issues" else _STATUS_TEXT[status]
    return f'<span class="status {status}">{text}</span>'


def _groups_sections(report: dict, groups: list[dict]) -> str:
    """Summary tables by test target and by OWASP Top 10, then the findings by test target."""
    findings = report["findings"]
    rank = {sev: i for i, sev in enumerate(_SEVERITIES)}
    head = "".join(f"<th>{sev}</th>" for sev in _SEVERITIES)
    target_rows = "".join(
        f'<tr><td><a href="#group-{g["id"]}">{_e(g["title"])}</a></td>'
        f"<td>{_status(g['status'], len(g['findings']))}</td>{_count_cells(g['counts'])}</tr>"
        for g in groups
    )
    owasp_rows = (
        "".join(
            f'<tr><td>{_e(g["title"])}</td>{_count_cells(g["counts"])}<td class="ids">'
            + ", ".join(f'<a href="#finding-{i}">{_e(findings[i].get("id"))}</a>' for i in g["findings"])
            + "</td></tr>"
            for g in owasp_groups(report)
        )
        or f'<tr><td colspan="{len(_SEVERITIES) + 2}" class="muted">No findings.</td></tr>'
    )

    sections = []
    for g in groups:
        ordered = sorted(g["findings"], key=lambda i: rank.get(findings[i].get("severity"), len(rank)))
        body = "".join(_finding(findings[i], i) for i in ordered)
        if not body:
            body = f'<p class="muted">{_e(_STATUS_NOTE[g["status"]])}</p>'
        sections.append(
            f'<h3 class="group" id="group-{g["id"]}">{_e(g["title"])}{_status(g["status"], len(g["findings"]))}</h3>'
            f'<p class="muted group-desc">{_e(g["description"])}</p>{body}'
        )
    return (
        "<h2>Summary by test target</h2>"
        f'<table class="groups"><tr><th>Test target</th><th>Status</th>{head}</tr>{target_rows}</table>'
        "<h2>Summary by OWASP Top 10</h2>"
        f'<table class="groups"><tr><th>OWASP category</th>{head}<th>Findings</th></tr>{owasp_rows}</table>'
        "<h2>Findings by test target</h2>" + "".join(sections)
    )


def _text(value) -> str:
    """Text that came from a spec file or a scanned site: control characters made visible, then escaped."""
    return _e(printable_text(value))


def _number(value) -> str:
    return f"{value:g}"


def _limits_text(limits: dict) -> str:
    parts = []
    if limits.get("rate_limit") is not None:
        parts.append(f"rate limit {_number(limits['rate_limit'])} requests/s")
    if limits.get("max_requests") is not None:
        parts.append(f"max {limits['max_requests']} requests")
    if limits.get("max_duration") is not None:
        parts.append(f"max {_number(limits['max_duration'])} s")
    return ", ".join(parts) or "none set"


_STOPPED_BY = {"max-requests": "--max-requests", "max-duration": "--max-duration"}


def _scan_detail_rows(report: dict) -> str:
    """FR-REPORT-09: what produced this report and what the scan was allowed to do; only what the report carries."""
    rows = []
    for label, key in (
        ("Scanner version", "scanner_version"),
        ("Rules version", "rules_version"),
        ("Scan ID", "scan_id"),
    ):
        if report.get(key):
            rows.append((label, _e(report[key])))
    limits = report.get("limits")
    if limits:
        rows.append(("Requests sent", _e(limits["requests_sent"])))
        rows.append(("Limits", _e(_limits_text(limits))))
        if limits.get("slowdowns"):
            rows.append(("Backed off", f"{_e(limits['slowdowns'])} time(s) after HTTP 429 or 503 answers"))
        if limits.get("stopped_by"):
            rows.append(("Stopped early by", _e(_STOPPED_BY.get(limits["stopped_by"], limits["stopped_by"]))))
    return "".join(f"<tr><th>{label}</th><td>{value}</td></tr>" for label, value in rows)


def _api(api: dict | None) -> str:
    """FR-REPORT-09: the inventory read from --api-spec. Every text in it came from a file, so none is trusted."""
    if not api:
        return ""
    head = (
        f"<p>{_text(api['title'])} "
        f'<span class="muted">({_text(api["format"])} {_text(api["version"])}, from {_text(api["source"])})</span></p>'
        '<p class="muted">Read from the spec file only: no request was sent to any endpoint or server it names.</p>'
    )
    if api["servers"]:
        head += "<p>Servers: " + ", ".join(f"<code>{_text(s)}</code>" for s in api["servers"]) + "</p>"
    if api["security_schemes"]:
        schemes = (
            f"{_text(s['name'])} ({_text(s['type'])}, {_text(s['detail'])})"
            if s["detail"]
            else f"{_text(s['name'])} ({_text(s['type'])})"
            for s in api["security_schemes"]
        )
        head += "<p>Security schemes: " + ", ".join(schemes) + "</p>"
    if not api["endpoints"]:
        return f'<h2>API inventory</h2><div class="card">{head}<p>No endpoints declared.</p></div>'
    rows = []
    for endpoint in api["endpoints"][:API_LISTED_ENDPOINTS]:
        params = ", ".join(f"{_text(p['name'])} ({_text(p['in'])})" for p in endpoint["parameters"]) or "-"
        auth = ", ".join(_text(name) for name in endpoint["security"]) or "none declared"
        flag = ' <span class="muted">deprecated</span>' if endpoint["deprecated"] else ""
        rows.append(
            f'<tr class="endpoint"><td>{_text(endpoint["method"])}</td>'
            f"<td><code>{_text(endpoint['path'])}</code>{flag}</td>"
            f"<td>{params}</td><td>{auth}</td></tr>"
        )
    more = api["endpoint_count"] - API_LISTED_ENDPOINTS
    tail = f"<p>... and {more} more endpoint(s); all of them are in the JSON report.</p>" if more > 0 else ""
    return (
        f'<h2>API inventory</h2><div class="card">{head}<p>{api["endpoint_count"]} endpoint(s):</p>'
        '<table class="api"><tr><th>Method</th><th>Path</th><th>Parameters</th><th>Auth</th></tr>'
        + "".join(rows)
        + f"</table>{tail}</div>"
    )


def _crawl(crawl: dict | None) -> str:
    """FR-CRAWL-01: what the crawl covered, why it stopped, and what it left alone."""
    if not crawl:
        return ""
    robots = "followed" if crawl["respect_robots"] else "ignored (--ignore-robots)"
    skipped = "".join(
        f"<li>{count} &times; {_e(CRAWL_SKIP_TEXT.get(reason, reason))}</li>"
        for reason, count in crawl["skipped"].items()
    )
    return (
        "<h2>Crawl</h2>"
        f'<div class="card"><p>{crawl["pages_visited"]} page(s) visited: '
        f"{_e(CRAWL_STOP_TEXT[crawl['stopped_reason']])}.</p>"
        f'<p class="muted">Limits: depth {crawl["max_depth"]}, {crawl["max_pages"]} pages, '
        f"{crawl['max_duration']:g} s; robots.txt {_e(robots)}.</p>"
        + (f'<p>Links not followed:</p><ul class="errors">{skipped}</ul>' if skipped else "")
        + "</div>"
    )


def render_html(report: dict) -> str:
    """Render a report dict of output.build_report() as a standalone HTML document."""
    counts = report.get("summary", {})
    findings = report.get("findings", [])
    groups = group_findings(report)
    gate_class, gate_text = gate_message(report["gate"])
    secrets_banner = (
        '<p class="gate fail">Secrets are not redacted in this report (--show-secrets). Do not share it.</p>'
        if report.get("secrets_redacted") is False
        else ""
    )

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
    findings_html = _groups_sections(report, groups)
    # Only worth explaining when the report actually carries scores (FR-MODEL-03).
    cvss_note = f"{_e(CVSS_NOTE)}<br><br>" if any(f.get("cvss_vector") for f in findings) else ""
    tested = ", ".join(g["title"] for g in groups if g["status"] != "not-selected")
    skipped = ", ".join(g["title"] for g in groups if g["status"] == "not-selected")
    scope_rows = f"<tr><th>Test targets</th><td>{_e(tested)}</td></tr>" + (
        f"<tr><th>Not selected (not tested)</th><td>{_e(skipped)}</td></tr>" if skipped else ""
    )
    checks = ", ".join(report.get("checks_run", [])) or "None"
    final_url = report.get("final_url") or ""
    final_row = (
        f"<tr><th>Final URL</th><td>{_e(final_url)}</td></tr>"
        if final_url and final_url != report.get("target")
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Non-intrusive web security scan report - {_e(report.get("target"))}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>Non-intrusive Web Security Scan Report</h1>
<p class="target">{_e(report.get("target"))}</p>
<div class="card">
<table class="meta">
<tr><th>Started (UTC)</th><td>{_e(report.get("started_at"))}</td></tr>
<tr><th>Finished (UTC)</th><td>{_e(report.get("finished_at"))}</td></tr>
{final_row}{scope_rows}<tr><th>Checks run</th><td>{_e(checks)}</td></tr>
<tr><th>Total findings</th><td>{len(findings)}</td></tr>{_scan_detail_rows(report)}
</table>
{secrets_banner}<p class="gate {gate_class}">{_e(gate_text)}</p>
<table class="summary"><tr>{summary_cells}</tr></table>
</div>
{_top_issues(findings)}
{_comparison(report.get("baseline"))}{_crawl(report.get("crawl"))}{_api(report.get("api"))}
{errors_html}
{findings_html}
<footer>
Generated by Non-intrusive Web Security Scanner {_e(__version__)}.
{cvss_note}{_e(SCOPE_NOTE)}
</footer>
</main>
</body>
</html>
"""
