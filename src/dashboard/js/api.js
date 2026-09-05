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

// Only http(s) findings references become links: scanner-controlled URLs
// with javascript:/data: schemes must render as inert text, never as
// clickable links.
function safeRefHref(r) {
  const s = String(r ?? "").trim();
  if (/^https?:\/\//i.test(s)) return s;
  return "";
}

function setLoading(el, on) {
  if (!el) return;
  el.classList.toggle("loading", !!on);
}

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.setAttribute("role", kind === "error" ? "alert" : "status");
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

async function loadProjects() {
  return get("/api/projects");
}

// ---------------------------------------------------------------- secret masking
// Defense-in-depth on top of server-side redaction: never let a raw secret or
// key leak into the DOM, even from older rows or fields the server missed.
const SECRET_PATTERNS = [
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----\s*(?:[^\n]*\n([^-]\n?)*)?[^\n]*-----END [A-Z ]*PRIVATE KEY-----/g, repl: "[REDACTED PRIVATE KEY]" },
  { re: /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, repl: (m) => m.slice(0, 4) + "\u25AA\u25AA\u25AA\u25AA" },
  { re: /\b[sprk]k_(live|test)_[0-9A-Za-z]{16,}\b/g, repl: "sk_$1_[MASKED]" },
  { re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g, repl: "$1_[MASKED]" },
  { re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, repl: "github_pat_[MASKED]" },
  { re: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/g, repl: "sk-[MASKED]" },
  { re: /\bxox[bapose]-[A-Za-z0-9-]{10,}\b/g, repl: "xox[MASKED]" },
  { re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_+/=-]+/g, repl: "[MASKED SLACK HOOK]" },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, repl: "AIza[MASKED]" },
  { re: /\b1\/\/0[0-9A-Za-z_-]{30,}\b/g, repl: "1//0[MASKED]" },
  { re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, repl: "glpat-[MASKED]" },
  { re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b/g, repl: "[MASKED JWT]" },
  { re: /(\bBearer\s+)[A-Za-z0-9._~+\/=-]{12,}/gi, repl: "$1[MASKED]" },
  { re: /(\bBasic\s+)[A-Za-z0-9+\/=]{8,}/gi, repl: "$1[MASKED]" },
  {
    re: /(\b(?:api[_-]?key|apikey|secret|token|password|passwd|pass|pwd|auth[_-]?(?:key|token)?|client[_-]?secret|private[_-]?key|access[_-]?key|aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|key)\b[\w-]*\s*[:=]\s*["']?)([^"'\s,;]{4,})/gi,
    repl: "$1[MASKED]",
  },
];

function maskSecrets(text) {
  let out = String(text ?? "");
  let masked = false;
  for (const p of SECRET_PATTERNS) {
    out = out.replace(p.re, (...args) => {
      masked = true;
      if (typeof p.repl === "function") return p.repl(...args);
      // Manual $N substitution: String.replace does this for literal repls,
      // but not when the replacer is a function.
      const captures = args.slice(1, -2);
      return p.repl.replace(/\$(\d+)/g, (_, n) => captures[parseInt(n, 10) - 1] ?? "");
    });
  }
  return { text: out, masked };
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
  const ev = f.evidence && typeof f.evidence === "object" ? f.evidence : {};
  const meta = [];
  if (f.cwe) meta.push(esc(f.cwe));
  if (ev.owasp) meta.push("OWASP " + esc(ev.owasp));
  if (ev.confidence) meta.push(esc(ev.confidence) + " confidence");
  const refs = (ev.references || []).slice(0, 5);
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
      <div class="modal-title mono">$> ${esc(f.rule_id || f.tool)}</div>
      <div class="muted mono">${loc}${meta.length ? " · " + meta.join(" · ") : ""}</div>
      ${f.description ? `<div class="explain-block"><div class="explain-label">// what is this</div><p class="modal-desc">${esc(f.description)}</p></div>` : ""}
      ${renderEvidence(f)}
      ${f.remediation ? `<div class="explain-block"><div class="explain-label">// how to fix</div><p>${esc(f.remediation)}</p></div>` : ""}
      ${refs.length ? `<div class="explain-block"><div class="explain-label">// references</div><ul class="ref-list">${refs.map((r) => { const h = safeRefHref(r); return h ? `<li><a href="${esc(h)}" target="_blank" rel="noopener noreferrer">${esc(r)}</a></li>` : `<li>${esc(r)}</li>`; }).join("")}</ul></div>` : ""}
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

// Render the vulnerable source excerpt with line numbers, vulnerable-line
// annotations ("bit explanations") and any secrets/keys masked out.
function renderEvidence(f) {
  const ev = f.evidence && typeof f.evidence === "object" ? f.evidence : {};
  const ctx = Array.isArray(ev.context) && ev.context.length ? ev.context : null;
  const rows = [];
  let maskedAny = false;

  if (ctx) {
    for (const c of ctx) {
      const m = maskSecrets(c.text);
      maskedAny = maskedAny || m.masked;
      rows.push(_snippetLine(c.line, m.text, !!c.vulnerable));
    }
  } else if (f.snippet) {
    const start = f.line_start || 1;
    f.snippet.split("\n").forEach((raw, i) => {
      const m = maskSecrets(raw);
      maskedAny = maskedAny || m.masked;
      rows.push(_snippetLine(start + i, m.text, false));
    });
  }

  if (!rows.length) return "";
  const banner = maskedAny
    ? `<div class="mask-banner" role="note">🔒 sensitive values detected — masked in this view</div>`
    : "";
  return `
    <div class="codeblock modal-code">
      <div class="explain-label">// vulnerable code</div>
      ${banner}
      <div class="snippet" dir="ltr">${rows.join("")}</div>
    </div>`;
}

function _snippetLine(ln, text, vulnerable) {
  return `<div class="sn-line${vulnerable ? " vuln" : ""}">
    <span class="sn-ln" aria-hidden="true">${ln}</span>
    <span class="sn-code">${text ? esc(text) : "&nbsp;"}</span>
    ${vulnerable ? '<span class="sn-tag" title="Flagged by the scanner">◂ flagged</span>' : ""}
  </div>`;
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
