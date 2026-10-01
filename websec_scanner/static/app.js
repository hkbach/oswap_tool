"use strict";

// Everything that comes back from a scan (headers, evidence, URLs) originates from
// the scanned site, so it is only ever rendered via textContent — never innerHTML.

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const LOCALE = "en-US";
// Group statuses computed by the server (output.group_findings), as shown to the user.
const STATUS_TEXT = {
  clean: "No issues",
  "not-run": "Not run",
  "not-selected": "Not selected",
};

const $ = (id) => document.getElementById(id);
let lastResult = null;
let groupsLoaded = false;

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

function groupBoxes() {
  return [...document.querySelectorAll("#groups-list input[type=checkbox]")];
}

function selectedGroups() {
  return groupBoxes().filter((box) => box.checked).map((box) => box.value);
}

function setBusy(busy, target) {
  $("scan-button").disabled = busy;
  $("target").disabled = busy;
  for (const box of groupBoxes()) box.disabled = busy;
  $("groups-all").disabled = busy;
  $("groups-none").disabled = busy;
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

// --- test target picker ----------------------------------------------------------

function updateGroupsCount() {
  const boxes = groupBoxes();
  $("groups-count").textContent = `${selectedGroups().length} of ${boxes.length} selected`;
}

function setAllGroups(checked) {
  for (const box of groupBoxes()) box.checked = checked;
  updateGroupsCount();
}

async function loadGroups() {
  try {
    const response = await fetch("/api/checks");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const { groups } = await response.json();
    const list = $("groups-list");
    list.replaceChildren();
    for (const group of groups) {
      const item = el("li", "group-option");
      const label = el("label");
      const box = el("input");
      box.type = "checkbox";
      box.value = group.id;
      box.checked = true;
      box.addEventListener("change", updateGroupsCount);
      const text = el("span", "group-option-text");
      text.append(el("span", "group-option-title", group.title), el("span", "group-option-desc", group.description));
      label.append(box, text);
      item.append(label);
      list.append(item);
    }
    groupsLoaded = true;
    $("groups-loading").hidden = true;
    updateGroupsCount();
  } catch (err) {
    $("groups-loading").textContent = "Could not load the list of test targets; a scan runs every test target.";
  }
}

// --- result rendering ------------------------------------------------------------

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

  const tested = result.groups.filter((g) => g.status !== "not-selected").map((g) => g.title);
  const skipped = result.groups.filter((g) => g.status === "not-selected").map((g) => g.title);
  $("scope").textContent =
    `Test targets: ${tested.join(", ")}` + (skipped.length ? ` · Not selected (not tested): ${skipped.join(", ")}` : "");
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

function findingItem(f, context) {
  const item = el("li", `finding sev-${f.severity.toLowerCase()}`);
  const head = el("div", "finding-head");
  head.append(el("span", "badge", f.severity), el("h4", "finding-title", f.title));
  item.append(head);
  // "estimated": the score is generic for this type of finding, not an assessment of this
  // target (FR-MODEL-03), the same wording the console and HTML reports use.
  const cvss = f.cvss_score == null ? "" : `CVSS 3.1 base: ${f.cvss_score} (estimated)`;
  const classification = [context, f.cwe, f.confidence ? `confidence ${f.confidence}` : "", cvss, f.id];
  item.append(el("p", "finding-owasp", classification.filter(Boolean).join(" · ")));
  item.append(el("p", "finding-desc", f.description));

  const details = el("dl", "details");
  if (f.evidence) details.append(detailRow("Evidence", f.evidence, true));
  if (f.recommendation) details.append(detailRow("Recommendation", f.recommendation, false));
  if (f.url) details.append(detailRow("URL", f.url, true));
  const links = (f.references || []).filter((ref) => String(ref).startsWith("https://"));
  if (links.length) details.append(referencesRow(links));
  if (details.childElementCount) item.append(details);
  return item;
}

function severityCounts(counts) {
  const list = el("span", "group-counts");
  for (const sev of SEVERITIES) {
    if (counts[sev]) list.append(el("span", `mini sev-${sev.toLowerCase()}`, `${counts[sev]} ${sev}`));
  }
  return list;
}

function renderFindings() {
  const byTarget = $("group-by").value === "target";
  const filter = $("severity-filter").value;
  const groups = byTarget ? lastResult.groups : lastResult.owasp_groups;
  const findings = lastResult.findings;
  // The other grouping, shown on each finding: its OWASP category, or its test target.
  const targetOf = {};
  for (const g of lastResult.groups) for (const i of g.findings) targetOf[i] = g.title;

  const container = $("groups");
  container.replaceChildren();
  let shown = 0;
  for (const group of groups) {
    const matching = group.findings.filter((i) => filter === "ALL" || findings[i].severity === filter);
    shown += matching.length;
    const status = group.findings.length ? "issues" : group.status;

    const section = el("details", `group status-${status}`);
    section.open = matching.length > 0;
    const summary = el("summary", "group-head");
    const title = el("span", "group-title");
    title.append(el("span", "group-name", group.title));
    if (byTarget) title.append(el("span", "group-desc", group.description));
    const pill = el("span", `status-pill status-${status}`, status === "issues" ? plural(group.findings.length, "issue") : STATUS_TEXT[status]);
    summary.append(title, severityCounts(group.counts), pill);
    section.append(summary);

    if (matching.length) {
      const list = el("ol", "findings");
      for (const i of matching) {
        const f = findings[i];
        list.append(findingItem(f, byTarget ? f.owasp_category : targetOf[i]));
      }
      section.append(list);
    } else {
      const note = group.findings.length
        ? "No findings at this severity."
        : status === "clean"
          ? "Checked; nothing to report."
          : status === "not-run"
            ? "Selected, but it could not run for this target (for example TLS on a plain-HTTP site, or the home page could not be fetched)."
            : "Not selected for this scan: not tested.";
      section.append(el("p", "group-note", note));
    }
    container.append(section);
  }

  $("no-findings").hidden = findings.length > 0 && shown > 0;
  $("no-findings").textContent = findings.length === 0 ? "No findings." : "No findings at this severity.";
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

// --- scan ------------------------------------------------------------------------

async function runScan(event) {
  event.preventDefault();
  showFormError("");
  const target = $("target").value.trim();
  if (!target) {
    showFormError("Enter the URL or hostname to scan.");
    $("target").focus();
    return;
  }
  const checks = selectedGroups();
  if (groupsLoaded && checks.length === 0) {
    showFormError("Select at least one test target.");
    return;
  }
  if (!$("authorized").checked) {
    showFormError("Confirm that you are authorized to scan this target before running the scan.");
    return;
  }

  const payload = { target, authorized: true };
  if (groupsLoaded) payload.checks = checks;
  showReportLink(null); // the link always refers to the result shown below it
  setBusy(true, target);
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
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
  const { gate_failed, gate_status, gate_message, groups, owasp_groups, report_id, report_url, ...report } = lastResult;
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
$("group-by").addEventListener("change", renderFindings);
$("download-json").addEventListener("click", downloadJson);
$("groups-all").addEventListener("click", () => setAllGroups(true));
$("groups-none").addEventListener("click", () => setAllGroups(false));
loadGroups();
