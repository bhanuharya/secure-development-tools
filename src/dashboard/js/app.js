const state = {
  projects: [],
  project: null,
  branches: [],
  prs: [],
  targets: [],
  scan: null,
  findings: [],
  sse: null,
};

// ---------------------------------------------------------------- init
async function init() {
  bindUi();
  try {
    state.projects = await loadProjects();
    renderProjectSelect();
    applyDeepLink();
  } catch (e) {
    toast(e.message, "error");
    document.getElementById("project-select").innerHTML =
      '<option value="">No projects yet</option>';
  }
}

function applyDeepLink() {
  const params = new URLSearchParams(location.search);
  const pid = params.get("project");
  const sid = params.get("scan");
  if (sid) state.scan = { id: parseInt(sid, 10) || 0 };
  if (pid && state.projects.some((p) => p.id === parseInt(pid, 10))) {
    document.getElementById("project-select").value = pid;
    onProjectChange();
  } else {
    loadFindings();
  }
}

function bindUi() {
  document.getElementById("project-select").addEventListener("change", onProjectChange);
  document.getElementById("scan-type").addEventListener("change", onScanTypeChange);
  document.getElementById("ref-type").addEventListener("change", onRefTypeChange);
}

// ---------------------------------------------------------------- project
function renderProjectSelect() {
  const sel = document.getElementById("project-select");
  if (!state.projects.length) {
    sel.innerHTML = '<option value="">No projects registered</option>';
    return;
  }
  sel.innerHTML = state.projects
    .map((p) => `<option value="${p.id}">${
      p.workspace ? `${esc(p.workspace)}/${esc(p.repo_slug)}` : `${esc(p.name)} (upload)`
    }</option>`)
    .join("");
  onProjectChange();
}

async function onProjectChange() {
  const id = parseInt(document.getElementById("project-select").value, 10);
  state.project = state.projects.find((p) => p.id === id) || null;
  if (!state.project) return;
  if (!state.project.workspace) {
    // Standalone/uploaded project: no Bitbucket branches or PRs.
    state.branches = [];
    state.prs = [];
    document.getElementById("branch-select").innerHTML = '<option value="">-</option>';
    document.getElementById("pr-select").innerHTML = '<option value="">-</option>';
    await loadTargets();
    loadFindings();
    return;
  }
  await Promise.all([loadBranches(), loadPullRequests(), loadTargets()]);
  loadFindings();
}

async function loadBranches() {
  const p = state.project;
  const data = await get(`/api/bitbucket/${p.workspace}/${p.repo_slug}/branches`);
  state.branches = data.branches;
  const sel = document.getElementById("branch-select");
  sel.innerHTML = state.branches
    .map((b) => `<option value="${esc(b.name)}">${esc(b.name)}</option>`)
    .join("");
}

async function loadPullRequests() {
  const p = state.project;
  const data = await get(`/api/bitbucket/${p.workspace}/${p.repo_slug}/pullrequests`);
  state.prs = data.pullrequests;
  const sel = document.getElementById("pr-select");
  sel.innerHTML = state.prs.length
    ? state.prs.map((pr) =>
        `<option value="${pr.id}">#${pr.id} ${esc(pr.title || "")} (${esc(pr.source || "")})</option>`).join("")
    : '<option value="">No open PRs</option>';
}

async function loadTargets() {
  const data = await get(`/api/projects/${state.project.id}`);
  state.targets = data.targets || [];
  const sel = document.getElementById("target-select");
  sel.innerHTML = state.targets.length
    ? state.targets.map((t) =>
        `<option value="${t.id}">${esc(t.name || t.url)}${t.is_production ? " [PROD]" : ""}</option>`).join("")
    : '<option value="">No targets configured</option>';
}

// ---------------------------------------------------------------- config UI
function onScanTypeChange() {
  const type = document.getElementById("scan-type").value;
  const isDast = type === "dast";
  document.getElementById("sast-engines").classList.toggle("hidden", isDast);
  document.getElementById("dast-config").classList.toggle("hidden", !isDast);
  if (isDast) {
    document.getElementById("ref-type").value = "branch";
    onRefTypeChange();
  }
}

function onRefTypeChange() {
  const pr = document.getElementById("ref-type").value === "pr";
  document.getElementById("branch-group").classList.toggle("hidden", pr);
  document.getElementById("pr-group").classList.toggle("hidden", !pr);
}

function selectedEngines() {
  const list = [];
  if (document.getElementById("eng-bandit").checked) list.push("bandit");
  if (document.getElementById("eng-opengrep").checked) list.push("opengrep");
  if (document.getElementById("eng-trivy").checked) list.push("trivy");
  if (document.getElementById("eng-gitleaks").checked) list.push("gitleaks");
  return list;
}

// ---------------------------------------------------------------- start scan
async function startScan() {
  if (!state.project) return toast("Select a project first", "error");
  const type = document.getElementById("scan-type").value;
  const refType = document.getElementById("ref-type").value;
  const body = {
    project_id: state.project.id,
    scan_type: type,
    ref_type: refType,
    ref_name: refType === "pr"
      ? document.getElementById("pr-select").value
      : document.getElementById("branch-select").value,
    language_override: document.getElementById("lang-override").value.trim(),
    dast_confirmed: document.getElementById("dast-confirm").checked,
  };
  if (type === "sast") body.engines = selectedEngines().filter((e) => e !== "zap");
  if (type === "dast") body.dast_target = parseInt(document.getElementById("target-select").value, 10) || null;

  try {
    const scan = await post("/api/scans", body);
    state.scan = scan;
    showProgress(scan);
    watchScan(scan.id);
  } catch (e) {
    toast(e.message, "error");
  }
}

// ---------------------------------------------------------------- progress
function showProgress(scan) {
  document.getElementById("progress-panel").classList.remove("hidden");
  document.getElementById("scan-status-label").textContent = "";
  document.getElementById("engine-chips").innerHTML = engineChips();
  document.getElementById("progress-note").textContent = "Starting scan...";
  document.getElementById("zap-progress").classList.add("hidden");
}

function engineChips() {
  const engines = state.scan.engines ? state.scan.engines.split(",") : ["bandit", "opengrep"];
  return engines
    .map((e) => `<span class="engine-chip queued" data-eng="${esc(e)}">${esc(e)}</span>`)
    .join("");
}

function watchScan(scanId) {
  if (state.sse) state.sse.close();
  const src = new EventSource(`/api/scans/${scanId}/events`);
  state.sse = src;
  src.addEventListener("scan_status", (ev) => {
    const data = JSON.parse(ev.data);
    document.getElementById("scan-status-label").textContent = "(" + data.status + ")";
    if (data.error) document.getElementById("progress-note").textContent = "Error: " + data.error;
  });
  src.addEventListener("engine_status", (ev) => {
    const data = JSON.parse(ev.data);
    const chip = document.querySelector(`.engine-chip[data-eng="${data.engine}"]`);
    if (chip) {
      chip.className = "engine-chip " + (data.state || "queued");
      chip.textContent = `${data.engine}${data.findings != null ? " (" + data.findings + ")" : ""}`;
    }
    if (data.state === "done" || data.state === "error") loadFindings();
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
      data.status === "running" ? "Cloning repository..." : "Clone complete";
  });
  src.addEventListener("__end__", () => {
    src.close();
    document.getElementById("progress-note").textContent = "Scan finished.";
    loadScans();
    loadFindings();
  });
}

// ---------------------------------------------------------------- findings
async function loadFindings() {
  if (!state.project) return;
  const params = new URLSearchParams({ scan_id: state.scan ? state.scan.id : "" });
  const st = document.getElementById("f-status").value;
  const sev = document.getElementById("f-severity").value;
  const pr = document.getElementById("f-pr").value;
  if (st) params.set("status", st);
  if (sev) params.set("severity", sev);
  if (pr !== "") params.set("pr_changed", pr);
  let findings = [];
  try {
    findings = await get(`/api/findings?${params}`);
  } catch (e) {
    findings = [];
  }
  state.findings = findings;
  renderFindings();
}

function renderFindings() {
  const body = document.getElementById("findings-body");
  document.getElementById("findings-empty").classList.toggle("hidden", state.findings.length > 0);
  document.getElementById("findings-count").textContent = state.findings.length
    ? `(${state.findings.length} shown)` : "";
  body.innerHTML = state.findings.map((f) => {
    const loc = `${esc(f.file_path || "")}${f.line_start ? ":" + f.line_start : ""}`;
    return `<tr>
      <td><span class="badge ${sevClass(f.severity)}">${esc(f.severity)}</span>
        ${f.in_pr_diff ? '<span class="badge pr">PR</span>' : ""}</td>
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
  const f = state.findings.find((x) => x.id === id);
  if (!f) return;
  showFindingModal(f, (status) => triage(id, status));
}

async function triage(id, status) {
  try {
    await patch(`/api/findings/${id}`, { status });
    toast("Finding updated", "success");
    loadFindings();
  } catch (e) {
    toast(e.message, "error");
  }
}

// ---------------------------------------------------------------- reports
async function generateScanReport() {
  if (!state.scan) return toast("Run a scan first", "error");
  try {
    const res = await post(`/api/reports/scan/${state.scan.id}`, {});
    window.open(res.file, "_blank");
  } catch (e) {
    toast(e.message, "error");
  }
}

async function generateProjectReport() {
  if (!state.project) return toast("Select a project first", "error");
  try {
    const res = await post(`/api/reports/project/${state.project.id}`, { pr_only: false });
    window.open(res.file, "_blank");
  } catch (e) {
    toast(e.message, "error");
  }
}

// scans list not critical for v1 UI; keep a lightweight refresh
async function loadScans() { /* hook for future scan history */ }

init();
