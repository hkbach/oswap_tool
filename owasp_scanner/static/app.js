"use strict";

// Everything that comes back from a scan (headers, evidence, URLs) originates from
// the scanned site, so it is only ever rendered via textContent — never innerHTML.

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const LOCALE = "en-US";

const $ = (id) => document.getElementById(id);
let lastResult = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function showFormError(message) {
  $("form-error").textContent = message;
  $("form-error").hidden = !message;
}

function setBusy(busy, target) {
  $("scan-button").disabled = busy;
  $("target").disabled = busy;
  $("status").hidden = !busy;
  $("status-text").textContent = busy ? `Scanning ${target}… this can take up to a minute.` : "";
}

function formatTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString(LOCALE, { timeZoneName: "short" });
}

function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

function showReportLink(result) {
  const row = $("report-link-row");
  if (!result || !result.report_url) {
    row.hidden = true;
    $("report-link").removeAttribute("href");
    return;
  }
  $("report-link").href = result.report_url;
  row.hidden = false;
}

function renderSummary(result) {
  const summary = $("summary");
  summary.replaceChildren();
  for (const sev of SEVERITIES) {
    const item = el("li", `chip sev-${sev.toLowerCase()}`);
    item.append(el("span", "chip-count", String(result.summary[sev] ?? 0)), el("span", "chip-label", sev));
    summary.append(item);
  }

  // The server sends the same gate text as the HTML report (output.gate_message).
  const gate = $("gate");
  gate.className = `gate gate-${result.gate_status}`;
  gate.textContent = result.gate_message;
}

function renderErrors(result) {
  const list = $("error-list");
  list.replaceChildren(...result.errors.map((e) => el("li", null, e)));
  $("errors").hidden = result.errors.length === 0;
}

function detailRow(label, value, asCode) {
  const row = el("div", "detail");
  row.append(el("dt", null, label));
  const dd = el("dd");
  dd.append(asCode ? el("code", null, value) : document.createTextNode(value));
  row.append(dd);
  return row;
}

function referencesRow(links) {
  const row = el("div", "detail");
  row.append(el("dt", null, "References"));
  const dd = el("dd", "references");
  for (const ref of links) {
    const link = el("a", null, ref);
    link.href = ref;
    link.rel = "noopener noreferrer";
    link.target = "_blank";
    dd.append(link);
  }
  row.append(dd);
  return row;
}

function renderFindings() {
  const filter = $("severity-filter").value;
  const findings = lastResult.findings.filter((f) => filter === "ALL" || f.severity === filter);
  const list = $("findings");
  list.replaceChildren();

  for (const f of findings) {
    const item = el("li", `finding sev-${f.severity.toLowerCase()}`);
    const head = el("div", "finding-head");
    head.append(el("span", "badge", f.severity), el("h3", "finding-title", f.title));
    item.append(head);
    const classification = [f.owasp_category, f.cwe, f.confidence ? `confidence ${f.confidence}` : "", f.id];
    item.append(el("p", "finding-owasp", classification.filter(Boolean).join(" · ")));
    item.append(el("p", "finding-desc", f.description));

    const details = el("dl", "details");
    if (f.evidence) details.append(detailRow("Evidence", f.evidence, true));
    if (f.recommendation) details.append(detailRow("Recommendation", f.recommendation, false));
    if (f.url) details.append(detailRow("URL", f.url, true));
    const links = (f.references || []).filter((ref) => String(ref).startsWith("https://"));
    if (links.length) details.append(referencesRow(links));
    if (details.childElementCount) item.append(details);
    list.append(item);
  }
  $("no-findings").hidden = findings.length > 0;
  $("no-findings").textContent =
    lastResult.findings.length === 0 ? "No findings." : "No findings at this severity.";
}

function renderResult(result) {
  lastResult = result;
  $("result-target").textContent = result.target;
  $("result-meta").textContent =
    `Started ${formatTime(result.started_at)} · Finished ${formatTime(result.finished_at)} · ` +
    plural(result.findings.length, "finding");
  const checks = result.checks_run.length ? `Checks run: ${result.checks_run.join(", ")}` : "No checks ran.";
  const redirected = result.final_url && result.final_url !== result.target;
  $("checks-run").textContent = redirected ? `Final URL: ${result.final_url} · ${checks}` : checks;
  renderSummary(result);
  renderErrors(result);
  $("severity-filter").value = "ALL";
  renderFindings();
  showReportLink(result);
  $("results").hidden = false;
}

async function runScan(event) {
  event.preventDefault();
  showFormError("");
  const target = $("target").value.trim();
  if (!target) {
    showFormError("Enter the URL or hostname to scan.");
    $("target").focus();
    return;
  }
  if (!$("authorized").checked) {
    showFormError("Confirm that you are authorized to scan this target before running the scan.");
    return;
  }

  showReportLink(null); // the link always refers to the result shown below it
  setBusy(true, target);
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, authorized: true }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      showFormError(data.error || `Server error (HTTP ${response.status}).`);
      if (lastResult) showReportLink(lastResult);
      return;
    }
    renderResult(data);
  } catch (err) {
    showFormError("Could not reach the scanner server. Is it still running?");
    if (lastResult) showReportLink(lastResult);
  } finally {
    setBusy(false, target);
  }
}

function downloadJson() {
  if (!lastResult) return;
  // Same shape as the CLI --json report: drop the UI-only fields (web.WEB_ONLY_FIELDS).
  const { gate_failed, gate_status, gate_message, report_id, report_url, ...report } = lastResult;
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const link = el("a");
  link.href = URL.createObjectURL(blob);
  const host = (() => { try { return new URL(report.target).host; } catch { return "report"; } })();
  link.download = `owasp-scan-${host.replace(/[^a-z0-9.-]/gi, "_")}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

$("scan-form").addEventListener("submit", runScan);
$("severity-filter").addEventListener("change", renderFindings);
$("download-json").addEventListener("click", downloadJson);
