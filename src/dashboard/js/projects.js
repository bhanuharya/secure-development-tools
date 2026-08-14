const projState = { projects: [], repos: [], cursor: null };

async function init() {
  bind();
  projState.projects = await loadProjects();
  renderProjects();
  renderTargetProjectSelect();
  document.getElementById("auth-mode").addEventListener("change", onAuthModeChange);
}

function bind() {
  document.getElementById("load-repos").addEventListener("click", loadRepos);
  document.getElementById("repo-list").addEventListener("change", enableRegister);
  document.getElementById("project-name").addEventListener("input", enableRegister);
  document.getElementById("workspace").addEventListener("input", enableRegister);
}

function enableRegister() {
  const hasRepo = !!document.getElementById("repo-list").value;
  const hasWs = !!document.getElementById("workspace").value.trim();
  document.getElementById("register-btn").disabled = !(hasRepo && hasWs);
}

async function loadRepos() {
  const ws = document.getElementById("workspace").value.trim();
  if (!ws) return toast("Enter a workspace first", "error");
  projState.repos = [];
  projState.cursor = null;
  document.getElementById("load-repos").textContent = "Loading...";
  try {
    await fetchMoreRepos();
    document.getElementById("load-repos").textContent =
      projState.cursor ? "Load more" : "Load repositories";
  } catch (e) {
    toast(e.message, "error");
    document.getElementById("load-repos").textContent = "Load repositories";
  }
}

async function fetchMoreRepos() {
  const ws = document.getElementById("workspace").value.trim();
  const q = projState.cursor ? `&cursor=${encodeURIComponent(projState.cursor)}` : "";
  const data = await get(`/api/bitbucket/${encodeURIComponent(ws)}/repos?${q.replace(/^\&/, "")}`);
  projState.repos = projState.repos.concat(data.repos);
  projState.cursor = data.next;
  const sel = document.getElementById("repo-list");
  sel.innerHTML = projState.repos
    .map((r) => `<option value="${esc(r.slug)}">${esc(r.slug)}${r.language ? "  (" + esc(r.language) + ")" : ""}</option>`)
    .join("");
  enableRegister();
}

async function registerProject() {
  const ws = document.getElementById("workspace").value.trim();
  const slug = document.getElementById("repo-list").value;
  const name = document.getElementById("project-name").value.trim();
  const msg = document.getElementById("register-msg");
  try {
    const project = await post("/api/projects", { workspace: ws, repo_slug: slug, name });
    msg.classList.remove("hidden");
    msg.innerHTML = `Registered <b>${esc(project.workspace)}/${esc(project.repo_slug)}</b> (id ${project.id}). ` +
      '<a href="/index.html" style="color:#38bdf8">Go to dashboard</a>';
    msg.className = "toast success";
    setTimeout(() => { msg.className = "hidden"; }, 5000);
    projState.projects.push(project);
    renderProjects();
  } catch (e) {
    toast(e.message, "error");
  }
}

function renderProjects() {
  const body = document.getElementById("projects-body");
  const empty = document.getElementById("projects-empty");
  if (empty) empty.classList.toggle("hidden", projState.projects.length > 0);
  body.innerHTML = projState.projects
    .map((p) => {
      const repo = p.workspace
        ? `${esc(p.workspace)}/${esc(p.repo_slug)}`
        : `<span class="badge pr">upload</span> ${esc(p.name)}`;
      return `<tr>
        <td>${esc(p.name)}</td>
        <td class="mono">${repo}</td>
        <td>${esc(p.default_branch)}</td>
        <td>${esc(p.languages || "-")}</td>
        <td>${p.targets ? p.targets.length : "-"}</td>
      </tr>`;
    })
    .join("");
}

function renderTargetProjectSelect() {
  const sel = document.getElementById("target-project");
  sel.innerHTML = projState.projects.length
    ? projState.projects
        .map((p) => `<option value="${p.id}">${esc(p.workspace)}/${esc(p.repo_slug)}</option>`)
        .join("")
    : '<option value="">No projects yet — register one</option>';
}

function onAuthModeChange() {
  const mode = document.getElementById("auth-mode").value;
  document.getElementById("form-auth").classList.toggle("hidden", mode !== "form");
  document.getElementById("context-auth").classList.toggle("hidden", mode !== "context_file");
}

async function saveTarget() {
  const pid = parseInt(document.getElementById("target-project").value, 10);
  if (!pid) return toast("Register a project first", "error");
  const url = document.getElementById("target-url").value.trim();
  if (!url) return toast("Target URL is required", "error");
  const mode = document.getElementById("auth-mode").value;
  const body = {
    project_id: pid,
    name: document.getElementById("target-name").value.trim() || url,
    url,
    auth_mode: mode,
    is_production: document.getElementById("is-production").checked,
    pre_approved: document.getElementById("pre-approved").checked,
  };
  if (mode === "form") {
    body.login_url = document.getElementById("login-url").value.trim() || url;
    body.username_field = document.getElementById("user-field").value.trim();
    body.password_field = document.getElementById("pass-field").value.trim();
    body.auth_username = document.getElementById("auth-user").value.trim();
    body.auth_password = document.getElementById("auth-pass").value;
  }
  if (mode === "context_file") {
    body.context_file_path = document.getElementById("context-file").value.trim();
  }
  try {
    await post(`/api/projects/${pid}/targets`, body);
    toast("Target added", "success");
    projState.projects = await loadProjects();
    renderProjects();
  } catch (e) {
    toast(e.message, "error");
  }
}

init();
