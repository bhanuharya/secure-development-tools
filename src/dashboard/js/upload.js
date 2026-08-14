const upState = { scan: null, sse: null, findings: [], pollTimer: null, engineRows: {} };

const ENGINE_INFO = {
  bandit: { name: "Bandit", desc: "Python code security" },
  opengrep: { name: "OpenGrep / Semgrep", desc: "Multi-language code security" },
  trivy: { name: "Trivy", desc: "Dependency vulnerabilities" },
  gitleaks: { name: "Gitleaks", desc: "Secrets & credentials" },
};

const PRESETS = {
  full: { label: "Full scan", engines: ["bandit", "opengrep", "trivy", "gitleaks"] },
  sast: { label: "Code security", engines: ["bandit", "opengrep"] },
  dependencies: { label: "Dependencies", engines: ["trivy"] },
  secrets: { label: "Secrets", engines: ["gitleaks"] },
};

// ---------------------------------------------------------------- init
function bindUi() {
  document.getElementById("dast-auth-mode").addEventListener("change", onDastAuthModeChange);
  document.querySelectorAll('input[name="preset"]').forEach((r) => r.addEventListener("change", onPresetChange));
  document.getElementById("dropzone").addEventListener("click", () => document.getElementById("up-file").click());
  document.getElementById("up-file").addEventListener("change", onFileSelect);
  document.getElementById("file-remove").addEventListener("click", removeFile);
  ["dragenter", "dragover"].forEach((ev) =>
    document.getElementById("dropzone").addEventListener(ev, (e) => {
      e.preventDefault();
      document.getElementById("dropzone").classList.add("dragging");
    })
  );
  ["dragleave", "drop"].forEach((ev) =>
    document.getElementById("dropzone").addEventListener(ev, (e) => {
      e.preventDefault();
      document.getElementById("dropzone").classList.remove("dragging");
    })
  );
  document.getElementById("dropzone").addEventListener("drop", (e) => {
    if (e.dataTransfer.files.length) {
      document.getElementById("up-file").files = e.dataTransfer.files;
      onFileSelect();
    }
  });
  loadScannerStatus();
}

function onPresetChange() {
  const preset = selectedPreset();
  const custom = preset === "custom";
  document.getElementById("custom-details").open = custom;
  if (!custom) {
    const engines = PRESETS[preset].engines;
    document.getElementById("up-engines").querySelectorAll("input[type=checkbox]").forEach((cb) => {
      cb.checked = engines.includes(cb.dataset.eng);
    });
  }
}

function onDastAuthModeChange() {
  const mode = document.getElementById("dast-auth-mode").value;
  document.getElementById("dast-form-auth").classList.toggle("hidden", mode !== "form");
  document.getElementById("dast-context-auth").classList.toggle("hidden", mode !== "context_file");
}

function selectedPreset() {
  const r = document.querySelector('input[name="preset"]:checked');
  return r ? r.value : "full";
}

function onFileSelect() {
  const file = document.getElementById("up-file").files[0];
  if (!file) return;
  document.getElementById("file-name").textContent = file.name;
  document.getElementById("file-size").textContent = " · " + humanSize(file.size);
  document.getElementById("drop-hint").textContent = "Selected archive";
  document.getElementById("file-summary").classList.remove("hidden");
}

function removeFile() {
  document.getElementById("up-file").value = "";
  document.getElementById("file-summary").classList.add("hidden");
  document.getElementById("drop-hint").textContent = "Drag a .zip here, or click to browse";
}

function humanSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

function showMsg(id, text, kind) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = "toast " + (kind || "");
  setTimeout(() => { el.className = "hidden"; }, 6000);
}

async function loadScannerStatus() {
  const box = document.getElementById("scanner-status");
  try {
    const status = await get("/api/scanners/status");
    box.innerHTML = Object.keys(ENGINE_INFO).map((eng) => {
      const info = status[eng] || {};
      const avail = info.available;
      const cls = avail ? "done" : "unavailable";
      const label = avail ? "available" : "unavailable";
      const detail = eng === "opengrep" && info.implementation ? ` (${info.implementation})` : "";
      return `<span class="engine-chip ${cls}">${esc(ENGINE_INFO[eng].name)}${detail}: ${label}</span>`;
    }).join("");
  } catch (e) {
    box.innerHTML = `<span class="muted">Could not load scanner status: ${esc(e.message)}</span>`;
  }
}

// ---------------------------------------------------------------- upload repo
async function startUpload() {
  const file = document.getElementById("up-file").files[0];
  if (!file) return showMsg("up-msg", "Select a .zip file first", "error");
  if (!file.name.toLowerCase().endsWith(".zip")) return showMsg("up-msg", "Please upload a .zip archive", "error");

  const preset = selectedPreset();
  const fd = new FormData();
  fd.append("file", file);
  fd.append("name", document.getElementById("up-name").value.trim());
  fd.append("language_override", document.getElementById("up-lang").value.trim());
  if (preset === "custom") {
    fd.append("preset", "custom");
    fd.append("scan_type", "full");
    const checked = [...document.querySelectorAll("#up-engines input:checked")].map((c) => c.dataset.eng);
    if (!checked.length) return showMsg("up-msg", "Select at least one engine", "error");
    checked.forEach((e) => fd.append("engines", e));
  } else {
    fd.append("preset", preset);
  }

  const btn = document.getElementById("up-start");
  btn.disabled = true;
  btn.textContent = "Uploading…";
  try {
    const scan = await postFile("/api/uploads/scan", fd);
    upState.scan = scan;
    beginProgress(scan);
    showMsg("up-msg", `Scan #${scan.id} started for ${esc(scan.ref_name || "upload")}.`, "success");
  } catch (e) {
    showMsg("up-msg", e.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan uploaded repo";
  }
}

// ---------------------------------------------------------------- direct dast
async function startDast() {
  const url = document.getElementById("dast-url").value.trim();
  if (!url) return toast("Target URL is required", "error");
  const mode = document.getElementById("dast-auth-mode").value;
  const body = {
    name: document.getElementById("dast-name").value.trim(),
    url,
    auth_mode: mode,
    is_production: document.getElementById("dast-is-production").checked,
    pre_approved: document.getElementById("dast-pre-approved").checked,
    dast_confirmed: document.getElementById("dast-confirm").checked,
  };
  if (mode === "form") {
    body.login_url = document.getElementById("dast-login-url").value.trim() || url;
    body.username_field = document.getElementById("dast-user-field").value.trim();
    body.password_field = document.getElementById("dast-pass-field").value.trim();
    body.auth_username = document.getElementById("dast-auth-user").value.trim();
    body.auth_password = document.getElementById("dast-auth-pass").value;
  }
  if (mode === "context_file") {
    body.context_file_path = document.getElementById("dast-context-file").value.trim();
  }
  try {
    const scan = await post("/api/uploads/dast", body);
    upState.scan = scan;
    beginProgress(scan);
    showMsg("dast-msg", `DAST scan #${scan.id} started against ${esc(url)}.`, "success");
  } catch (e) {
    showMsg("dast-msg", e.message, "error");
  }
}

// ---------------------------------------------------------------- progress
function beginProgress(scan) {
  document.getElementById("progress-panel").classList.remove("hidden");
  document.getElementById("findings-panel").classList.remove("hidden");
  document.getElementById("scan-status-label").textContent = "";
  document.getElementById("progress-note").textContent = "Starting scan…";
  document.getElementById("zap-progress").classList.add("hidden");
  document.getElementById("scan-links").classList.add("hidden");
  document.getElementById("summary-panel").classList.add("hidden");
  upState.findings = [];
  upState.engineRows = {};
  renderEngineRows(scan.engines ? scan.engines.split(",") : []);
  renderFindings();
  watchScan(scan.id);
}

function renderEngineRows(engines) {
  const box = document.getElementById("engine-rows");
  box.innerHTML = engines.map((eng) => {
    const info = ENGINE_INFO[eng] || { name: eng, desc: "" };
    return `<div class="engine-row queued" data-eng="${esc(eng)}">
      <span class="engine-name">${esc(info.name)}</span>
      <span class="engine-desc muted">${esc(info.desc)}</span>
      <span class="engine-state">Waiting</span>
    </div>`;
  }).join("");
}

function setEngineState(eng, state, findings, reason) {
  const row = document.querySelector(`.engine-row[data-eng="${eng}"]`);
  if (!row) return;
  row.className = "engine-row " + state;
  const label = { running: "Running", done: "Complete", skipped: "Skipped", unavailable: "Unavailable", failed: "Failed", timeout: "Timed out" }[state] || state;
  let text = label;
  if (findings != null) text += " · " + findings + " findings";
  const st = row.querySelector(".engine-state");
  st.textContent = text;
  st.title = reason || "";
  if (reason) {
    let d = row.querySelector(".engine-reason");
    if (!d) {
      d = document.createElement("span");
      d.className = "engine-reason muted";
      row.appendChild(d);
    }
    d.textContent = reason;
  }
}

function watchScan(scanId) {
  if (upState.sse) upState.sse.close();
  const src = new EventSource(`/api/scans/${scanId}/events`);
  upState.sse = src;

  src.addEventListener("scan_status", (ev) => {
    const data = JSON.parse(ev.data);
    document.getElementById("scan-status-label").textContent = "(" + data.status + ")";
    if (data.error) document.getElementById("progress-note").textContent = "Error: " + data.error;
  });
  src.addEventListener("engine_status", (ev) => {
    const data = JSON.parse(ev.data);
    setEngineState(data.engine, data.state, data.findings, data.reason);
    if (data.state === "done" || data.state === "failed") loadFindings(scanId);
  });
  src.addEventListener("zap_progress", (ev) => {
    const data = JSON.parse(ev.data);
    document.getElementById("zap-progress").classList.remove("hidden");
    document.getElementById("zap-fill").style.width = data.percent + "%";
    document.getElementById("progress-note").textContent = `${data.stage}: ${data.percent}%`;
  });
  src.addEventListener("clone", (ev) => {
    const data = JSON.parse(ev.data);
    document.getElementById("progress-note").textContent =
      data.status === "running" ? (data.note || "Cloning repository...") : "Source code ready";
  });
  src.addEventListener("__end__", () => {
    src.close();
    finishScan(scanId);
  });
  src.onerror = () => {
    // EventSource auto-retries; fall back to polling after a short grace period.
    if (upState.pollTimer) return;
    upState.pollTimer = setInterval(() => pollScan(scanId), 3000);
  };
}

async function pollScan(scanId) {
  const scan = await get(`/api/scans/${scanId}`);
  if (scan && ["succeeded", "failed", "aborted"].includes(scan.status)) {
    clearInterval(upState.pollTimer);
    upState.pollTimer = null;
    finishScan(scanId);
  }
}

async function finishScan(scanId) {
  clearInterval(upState.pollTimer);
  upState.pollTimer = null;
  let scan;
  try {
    scan = await get(`/api/scans/${scanId}`);
  } catch (e) {
    scan = null;
  }
  document.getElementById("scan-status-label").textContent = scan ? "(" + scan.status + ")" : "";
  document.getElementById("progress-note").textContent =
    scan && scan.status === "failed" ? (scan.error || "Scan failed") : "Scan finished.";
  const link = document.getElementById("scan-dash-link");
  link.href = `/index.html?project=${upState.scan.project_id}&scan=${scanId}`;
  document.getElementById("scan-links").classList.remove("hidden");
  await loadFindings(scanId);
  renderSummary(scan);
}

function renderSummary(scan) {
  if (!scan) return;
  document.getElementById("summary-panel").classList.remove("hidden");
  const title = document.getElementById("summary-title");
  const note = document.getElementById("summary-note");
  const cards = document.getElementById("summary-cards");

  const states = scan.engine_statuses ? JSON.parse(scan.engine_statuses) : {};
  const engineList = Object.keys(states);
  const done = engineList.filter((e) => states[e].state === "done").length;
  const failed = engineList.filter((e) => ["failed", "timeout", "unavailable"].includes(states[e].state)).length;

  if (scan.status === "failed") {
    title.textContent = "Scan failed";
    note.textContent = "No scanner completed successfully. See the engine statuses above.";
  } else if (failed > 0) {
    title.textContent = "Scan completed with warnings";
    note.textContent = `${failed} of ${engineList.length} scanner(s) did not complete. Review their status before treating this as clean.`;
  } else {
    title.textContent = "Scan completed";
    note.textContent = "All selected scanners completed successfully.";
  }

  const summary = scan.summary ? JSON.parse(scan.summary) : {};
  const total = summary.total || 0;
  const stats = [
    { value: total, label: "Findings" },
    { value: summary.critical || 0, label: "Critical" },
    { value: summary.high || 0, label: "High" },
    { value: summary.medium || 0, label: "Medium" },
    { value: summary.low || 0, label: "Low" },
    { value: `${done}/${engineList.length || "-"}`, label: "Engines ok" },
  ];
  if (summary.languages) stats.push({ value: summary.languages.join(", "), label: "Languages" });
  cards.innerHTML = stats.map((s) => `<div class="stat-card"><div class="value">${esc(String(s.value))}</div><div class="label">${esc(s.label)}</div></div>`).join("");

  if (total === 0 && scan.status !== "failed") {
    document.getElementById("findings-empty").textContent = failed
      ? "No findings available from completed scanners — some scanners did not complete."
      : "No findings detected. Automated scanning reduces risk but does not prove the repository is vulnerability-free.";
    document.getElementById("findings-empty").classList.remove("hidden");
  }
}

// ---------------------------------------------------------------- findings
async function loadFindings(scanId) {
  let findings = [];
  try {
    findings = await get(`/api/findings?scan_id=${scanId}`);
  } catch (e) {
    document.getElementById("findings-empty").textContent = "Results could not be loaded.";
    document.getElementById("findings-empty").classList.remove("hidden");
    return;
  }
  upState.findings = findings;
  renderFindings();
}

function renderFindings() {
  const body = document.getElementById("findings-body");
  const empty = document.getElementById("findings-empty");
  empty.classList.toggle("hidden", upState.findings.length > 0);
  document.getElementById("findings-count").textContent = upState.findings.length
    ? `(${upState.findings.length} shown)` : "";
  body.innerHTML = upState.findings.map((f) => {
    const loc = `${esc(f.file_path || "")}${f.line_start ? ":" + f.line_start : ""}`;
    return `<tr>
      <td><span class="badge ${sevClass(f.severity)}">${esc(f.severity)}</span></td>
      <td>${esc(f.tool)}</td>
      <td class="mono">${esc(f.rule_id || "")}${f.cwe ? `<br><span class="muted">${esc(f.cwe)}</span>` : ""}</td>
      <td class="mono">${loc}</td>
      <td>${f.line_start || ""}</td>
      <td><span class="badge ${f.status}">${esc(f.status)}</span></td>
      <td><button class="secondary" onclick="openFindingModal(${f.id})">details</button></td>
    </tr>`;
  }).join("");
}

function openFindingModal(id) {
  const f = upState.findings.find((x) => x.id === id);
  if (!f) return;
  showFindingModal(f, (status) => triageUpFinding(id, status));
}

async function triageUpFinding(id, status) {
  try {
    await patch(`/api/findings/${id}`, { status });
    toast("Finding updated", "success");
    if (upState.scan) loadFindings(upState.scan.id);
  } catch (e) {
    toast(e.message, "error");
  }
}

bindUi();
