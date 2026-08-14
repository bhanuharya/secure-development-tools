const API = "";

async function api(path, options = {}) {
  const opts = { headers: { "Content-Type": "application/json" }, ...options };
  const resp = await fetch(API + path, opts);
  if (resp.status === 204) return null;
  let body = null;
  try { body = await resp.json(); } catch (e) { /* empty body */ }
  if (!resp.ok) {
    const detail = body && (body.detail || body.message);
    throw new Error(detail || `HTTP ${resp.status}`);
  }
  return body;
}

const get = (p) => api(p);
const post = (p, data) => api(p, { method: "POST", body: JSON.stringify(data) });
const patch = (p, data) => api(p, { method: "PATCH", body: JSON.stringify(data) });
const postFile = (p, formData) => api(p, { method: "POST", body: formData, headers: {} });

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

function sevClass(s) { return ["critical", "high", "medium", "low", "info"].includes(s) ? s : "info"; }

function setLoading(el, on) {
  if (!el) return;
  el.classList.toggle("loading", !!on);
}

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

async function loadProjects() {
  return get("/api/projects");
}

// ---------------------------------------------------------------- finding modal
let _findingModal = null;

function _ensureFindingModal() {
  if (_findingModal) return _findingModal;
  const el = document.createElement("div");
  el.id = "finding-modal";
  el.className = "modal-overlay hidden";
  el.setAttribute("role", "dialog");
  el.setAttribute("aria-modal", "true");
  el.setAttribute("aria-label", "Finding details");
  document.body.appendChild(el);
  el.addEventListener("click", (e) => {
    if (e.target === el) closeFindingModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !el.classList.contains("hidden")) closeFindingModal();
  });
  _findingModal = el;
  return el;
}

function showFindingModal(f, triageFn) {
  const el = _ensureFindingModal();
  const loc = `${esc(f.file_path || "")}${f.line_start ? ":" + f.line_start : ""}`;
  el.innerHTML = `
    <div class="modal">
      <div class="modal-head">
        <div>
          <span class="badge ${sevClass(f.severity)}">${esc(f.severity)}</span>
          <span class="badge ${f.status}">${esc(f.status)}</span>
          <span class="modal-tool mono">${esc(f.tool)}</span>
        </div>
        <button class="secondary modal-close" aria-label="Close">×</button>
      </div>
      <div class="modal-title mono">${esc(f.rule_id || "")}</div>
      <div class="muted mono">${loc}${f.cwe ? ` · ${esc(f.cwe)}` : ""}</div>
      ${f.description ? `<p class="modal-desc">${esc(f.description)}</p>` : ""}
      ${f.snippet ? `<div class="codeblock modal-code">${esc(f.snippet)}</div>` : ""}
      ${f.remediation ? `<p><b>Remediation:</b> ${esc(f.remediation)}</p>` : ""}
      <div class="triage">
        <button onclick="triageModal(this, 'triaged')">triaged</button>
        <button onclick="triageModal(this, 'fixed')">fixed</button>
        <button onclick="triageModal(this, 'false_positive')">false positive</button>
        <button onclick="triageModal(this, 'accepted_risk')">accepted risk</button>
      </div>
    </div>`;
  el.classList.remove("hidden");
  document.body.classList.add("modal-open");
  const closeBtn = el.querySelector(".modal-close");
  if (closeBtn) closeBtn.onclick = closeFindingModal;
  el.dataset.triage = "";
  window.__findingTriage = triageFn || function () {};
}

function triageModal(btn, status) {
  if (typeof window.__findingTriage === "function") window.__findingTriage(status);
  closeFindingModal();
}

function closeFindingModal() {
  if (!_findingModal) return;
  _findingModal.classList.add("hidden");
  document.body.classList.remove("modal-open");
  window.__findingTriage = null;
}
