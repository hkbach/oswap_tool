"use strict";

// Everything that comes back from a scan (headers, evidence, URLs) originates from
// the scanned site, so it is only ever rendered via textContent — never innerHTML.

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

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
  $("status-text").textContent = busy ? `Đang quét ${target}… có thể mất vài chục giây.` : "";
}

function formatTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

function renderSummary(result) {
  const summary = $("summary");
  summary.replaceChildren();
  for (const sev of SEVERITIES) {
    const item = el("li", `chip sev-${sev.toLowerCase()}`);
    item.append(el("span", "chip-count", String(result.summary[sev] ?? 0)), el("span", "chip-label", sev));
    summary.append(item);
  }

  const gate = $("gate");
  const baselineFailed = result.errors.some((e) => e.startsWith("Could not fetch"));
  if (result.gate_failed) {
    gate.className = "gate gate-fail";
    gate.textContent = "Có finding CRITICAL/HIGH — CLI sẽ trả exit code 1 (fail CI gate).";
  } else if (baselineFailed) {
    gate.className = "gate gate-warn";
    gate.textContent = "Không tải được trang chủ target nên phần lớn check chưa chạy — xem mục lỗi bên dưới.";
  } else {
    gate.className = "gate gate-pass";
    gate.textContent = "Không có finding CRITICAL/HIGH — CLI sẽ trả exit code 0.";
  }
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
    item.append(el("p", "finding-owasp", `${f.owasp_category} · ${f.id}`));
    item.append(el("p", "finding-desc", f.description));

    const details = el("dl", "details");
    if (f.evidence) details.append(detailRow("Evidence", f.evidence, true));
    if (f.recommendation) details.append(detailRow("Cách khắc phục", f.recommendation, false));
    if (f.url) details.append(detailRow("URL", f.url, true));
    if (details.childElementCount) item.append(details);
    list.append(item);
  }
  $("no-findings").hidden = findings.length > 0;
  $("no-findings").textContent =
    lastResult.findings.length === 0 ? "Không có finding nào." : "Không có finding nào ở mức độ này.";
}

function renderResult(result) {
  lastResult = result;
  $("result-target").textContent = result.target;
  $("result-meta").textContent =
    `Bắt đầu ${formatTime(result.started_at)} · Kết thúc ${formatTime(result.finished_at)} · ` +
    `${result.findings.length} finding`;
  $("checks-run").textContent = result.checks_run.length
    ? `Các nhóm check đã chạy: ${result.checks_run.join(", ")}`
    : "Chưa có nhóm check nào chạy.";
  renderSummary(result);
  renderErrors(result);
  $("severity-filter").value = "ALL";
  renderFindings();
  $("results").hidden = false;
}

async function runScan(event) {
  event.preventDefault();
  showFormError("");
  const target = $("target").value.trim();
  if (!target) {
    showFormError("Nhập URL hoặc hostname cần quét.");
    $("target").focus();
    return;
  }
  if (!$("authorized").checked) {
    showFormError("Hãy xác nhận bạn có quyền quét target này trước khi chạy.");
    return;
  }

  setBusy(true, target);
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, authorized: true }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      showFormError(data.error || `Lỗi server (HTTP ${response.status}).`);
      return;
    }
    renderResult(data);
  } catch (err) {
    showFormError("Không kết nối được tới scanner server. Server còn đang chạy không?");
  } finally {
    setBusy(false, target);
  }
}

function downloadJson() {
  if (!lastResult) return;
  const { gate_failed, ...report } = lastResult; // same shape as the CLI --json report
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
