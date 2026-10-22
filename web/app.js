const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const queryToken = new URLSearchParams(location.search).get("token") || "";
if (queryToken) sessionStorage.setItem("php2shell.token", queryToken);
const token = queryToken || sessionStorage.getItem("php2shell.token") || "";
if (queryToken) history.replaceState(null, "", "/");

const state = {
  jobId: null,
  timer: null,
  results: [],
  report: null,
  selectedId: null,
};

const labels = {
  vulnerable: "存在漏洞",
  at_risk: "高风险 / EOL",
  unknown: "无法确认",
  fixed: "已修复",
  no_php: "未检测到 PHP",
  error: "扫描失败",
};

function headers(json = false) {
  const value = {};
  if (json) value["Content-Type"] = "application/json";
  if (token) value["X-Scanner-Token"] = token;
  return value;
}

function saveSettings() {
  const data = {
    servers: $("#servers").value,
    targets: $("#targets").value,
    keyPath: $("#keyPath").value,
    workers: $("#workers").value,
    timeout: $("#timeout").value,
    verifyTls: $("#verifyTls").checked,
  };
  localStorage.setItem("php2shell.scanner.settings", JSON.stringify(data));
}

function loadSettings() {
  try {
    const data = JSON.parse(localStorage.getItem("php2shell.scanner.settings") || "{}");
    if (data.servers) $("#servers").value = data.servers;
    if (data.targets) $("#targets").value = data.targets;
    if (data.keyPath) $("#keyPath").value = data.keyPath;
    if (data.workers) $("#workers").value = data.workers;
    if (data.timeout) $("#timeout").value = data.timeout;
    if (typeof data.verifyTls === "boolean") $("#verifyTls").checked = data.verifyTls;
  } catch (_) {
    // Ignore stale or malformed local settings.
  }
}

function showError(message = "") {
  const box = $("#errorBanner");
  if (!message) {
    box.textContent = "";
    box.classList.add("hidden");
    return;
  }
  box.textContent = message;
  box.classList.remove("hidden");
}

function setEngineState(text, running = false) {
  $("#engineState").textContent = text;
  $(".dot").style.background = running ? "var(--amber)" : "var(--green)";
  $(".dot").style.boxShadow = `0 0 14px ${running ? "var(--amber)" : "var(--green)"}`;
}

async function startScan() {
  saveSettings();
  showError("");
  $("#scanBtn").disabled = true;
  setEngineState("正在扫描", true);
  state.results = [];
  state.report = null;
  state.selectedId = null;
  $("#resultRows").innerHTML = "";
  $("#summary").classList.add("hidden");
  $("#resultsSection").classList.add("hidden");
  $("#detailContent").classList.add("hidden");
  $("#detailEmpty").classList.remove("hidden");
  setProgress(0, 0, "正在建立扫描任务…");
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: headers(true),
      body: JSON.stringify({
        servers_text: $("#servers").value,
        targets_text: $("#targets").value,
        default_key_path: $("#keyPath").value,
        workers: Number($("#workers").value || 8),
        timeout_sec: Number($("#timeout").value || 25),
        verify_tls: $("#verifyTls").checked,
      }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    state.jobId = payload.job_id;
    setProgress(0, payload.total, "扫描已启动");
    pollJob();
  } catch (error) {
    scanFailed(error.message || String(error));
  }
}

async function pollJob() {
  clearTimeout(state.timer);
  if (!state.jobId) return;
  try {
    const response = await fetch(`/api/jobs/${state.jobId}`, { headers: headers(false) });
    const job = await response.json();
    if (!response.ok) throw new Error(job.error || `HTTP ${response.status}`);
    state.results = job.results || [];
    state.report = job.report || null;
    renderResults(state.results, state.selectedId);
    renderSummary(job.summary || {});
    setProgress(job.progress || 0, job.total || 0, job.state === "done" ? "扫描完成" : "扫描进行中");
    if (job.state === "error") {
      throw new Error(job.error || "扫描失败");
    }
    if (job.state === "done") {
      $("#scanBtn").disabled = false;
      setEngineState("扫描完成", false);
      setProgress(
        job.total,
        job.total,
        `完成：漏洞 ${job.summary?.vulnerable || 0} / 风险 ${job.summary?.at_risk || 0} / 无法确认 ${job.summary?.unknown || 0} / 已修复 ${job.summary?.fixed || 0}`
      );
      return;
    }
    state.timer = setTimeout(pollJob, 1000);
  } catch (error) {
    scanFailed(error.message || String(error));
  }
}

function scanFailed(message) {
  clearTimeout(state.timer);
  $("#scanBtn").disabled = false;
  setEngineState("扫描失败", false);
  showError(message);
}

function setProgress(done, total, label) {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  $("#progressBar").style.width = `${pct}%`;
  $("#progressCount").textContent = `${done} / ${total}`;
  $("#progressText").textContent = label;
}

function renderSummary(summary) {
  if (!summary || !summary.total) return;
  $("#summary").classList.remove("hidden");
  $("#resultsSection").classList.remove("hidden");
  $("#statTotal").textContent = summary.total || 0;
  $("#statVulnerable").textContent = summary.vulnerable || 0;
  $("#statRisk").textContent = summary.at_risk || 0;
  $("#statFixed").textContent = summary.fixed || 0;
  $("#statUnknown").textContent = (summary.unknown || 0) + (summary.no_php || 0);
  $("#statError").textContent = summary.error || 0;
}

function runtimeText(result) {
  const runtimes = result.php_runtimes || [];
  if (!runtimes.length) return "—";
  return runtimes.map((item) => `${item.version || "unknown"} · ${item.sapi || ""}`).join("\n");
}

function findingText(result) {
  const findings = result.findings || [];
  if (findings.length) {
    return findings.map((item) => `${(item.cves || []).join(", ")} · ${item.reason || ""}`).join("\n");
  }
  if ((result.errors || []).length) return result.errors.join("\n");
  if (result.status === "fixed") return "运行时版本已达到修复版本";
  if (result.status === "no_php") return "未检测到运行中的 PHP";
  if (result.status === "unknown") return "响应头未暴露 PHP 版本，无法确认，需 SSH 复核";
  return "暂无足够证据";
}

function renderResults(results, selectedId = null) {
  const body = $("#resultRows");
  body.innerHTML = "";
  for (const result of results) {
    const tr = document.createElement("tr");
    if (result.id === selectedId) tr.classList.add("active");
    tr.addEventListener("click", () => {
      state.selectedId = result.id;
      renderResults(state.results, result.id);
      renderDetail(result);
    });
    tr.innerHTML = `
      <td><span class="pill ${escapeHTML(result.status || "unknown")}">${escapeHTML(labels[result.status] || result.status || "未知")}</span></td>
      <td><strong>${escapeHTML(result.name || "")}</strong><small>${escapeHTML(result.address || "")}</small></td>
      <td>${runtimeText(result).split("\n").map((x) => `<span class="runtime">${escapeHTML(x)}</span>`).join("")}</td>
      <td>${findingText(result).split("\n").map((x) => `<span class="runtime">${escapeHTML(x)}</span>`).join("")}</td>
    `;
    body.appendChild(tr);
  }
  if (selectedId) {
    const selected = results.find((item) => item.id === selectedId);
    if (selected) renderDetail(selected);
  }
}

function renderDetail(result) {
  $("#detailEmpty").classList.add("hidden");
  const box = $("#detailContent");
  box.classList.remove("hidden");
  const findings = (result.findings || []).map((item) => `
    <div class="finding-box">
      <strong>${escapeHTML((item.cves || []).join(" / "))}</strong><br>
      ${escapeHTML(item.reason || "")}
    </div>
  `).join("");
  const runtimes = (result.php_runtimes || []).map((item) => `
    <li><strong>${escapeHTML(item.version || "unknown")}</strong> · ${escapeHTML(item.sapi || "")}<br>
      <span class="detail-meta">${escapeHTML(item.path || "")} ${item.config ? ` · ${escapeHTML(JSON.stringify(item.config))}` : ""}</span>
    </li>
  `).join("");
  const fixes = (result.fixes || []).map((fix) => `
    <div class="detail-section">
      <h3>${escapeHTML(fix.title || "修复建议")}</h3>
      <ol>${(fix.steps || []).map((step) => `<li>${escapeHTML(step)}</li>`).join("")}</ol>
    </div>
  `).join("");
  const errors = (result.errors || []).length
    ? `<div class="detail-section"><h3>扫描信息</h3><div class="evidence">${escapeHTML((result.errors || []).join("\n"))}</div></div>`
    : "";
  const hostLine = result.hostname && result.hostname !== result.address
    ? `${escapeHTML(result.address || "")}<br>${escapeHTML(result.hostname || "")}`
    : escapeHTML(result.address || result.hostname || "");
  box.innerHTML = `
    <span class="pill ${escapeHTML(result.status || "unknown")}">${escapeHTML(labels[result.status] || result.status || "未知")}</span>
    <h2>${escapeHTML(result.name || "")}</h2>
    <div class="detail-meta">${hostLine}${result.os ? " · " + escapeHTML(result.os) : ""}</div>
    <div class="detail-section">
      <h3>PHP 运行时</h3>
      <ul>${runtimes || "<li>未检测到版本</li>"}</ul>
    </div>
    <div class="detail-section">
      <h3>判定依据</h3>
      ${findings || `<p>${escapeHTML(findingText(result))}</p>`}
    </div>
    ${fixes}
    ${errors}
    <details class="detail-section">
      <summary>查看原始证据</summary>
      <pre class="evidence">${escapeHTML(JSON.stringify(result.evidence || {}, null, 2))}</pre>
    </details>
  `;
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function exportReport(format) {
  if (!state.jobId || !state.report) return;
  try {
    const response = await fetch(`/api/jobs/${state.jobId}/report?format=${encodeURIComponent(format)}`, {
      headers: headers(false),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const extension = format === "md" ? "md" : format;
    anchor.download = `php2shell-report-${stamp}.${extension}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    showError(error.message || String(error));
  }
}

$("#scanBtn").addEventListener("click", startScan);
$("#loadServersBtn").addEventListener("click", () => $("#serversFile").click());
$("#loadTargetsBtn").addEventListener("click", () => $("#targetsFile").click());
$("#serversFile").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  $("#servers").value = await file.text();
  saveSettings();
});
$("#targetsFile").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  $("#targets").value = await file.text();
  saveSettings();
});
$$(".export-actions button").forEach((button) => {
  button.addEventListener("click", () => exportReport(button.dataset.format));
});
["#servers", "#targets", "#keyPath", "#workers", "#timeout", "#verifyTls"].forEach((selector) => {
  $(selector).addEventListener("change", saveSettings);
  $(selector).addEventListener("input", saveSettings);
});
loadSettings();
