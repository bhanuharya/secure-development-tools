# Secure SDLC Control Plane

A self-hosted **security scan orchestration platform** for a software delivery
workflow. You register a project (or ingest code directly), and the platform runs
multiple scanner engines — SAST, dependency/SCA, secrets, and DAST — collects
normalized findings, enforces evidence capture with **credential redaction**, and
generates reports.

Backed by **FastAPI + SQLModel (SQLite)** with a **vanilla-JS dashboard** (no
frontend build step). Everything runs locally / on your own network.

---

## Features

- **Multi-engine scanning** — per scan it can run, in parallel:
  - **SAST** — `bandit` (Python) and `opengrep` (multi-language; falls back to
    `semgrep` when its binary is available, and to a bundled local rule pack when
    offline).
  - **SCA / dependencies** — `trivy` image/fs vulnerability scanning.
  - **Secrets** — `gitleaks`.
  - **DAST** — `zap` (via the OWASP ZAP API).
- **Two intake paths**
  - **Bitbucket** — pick a workspace/repo/branch, optionally a pull-request diff
    (only changed lines are scanned), and run a scan.
  - **Upload** — push a source **ZIP**, or a **DAST target** (auth-protected URL),
    directly through the dashboard.
- **Evidence with redaction** — findings capture code context (source snippet +
  8 KiB cap), but **every credential-like value is redacted** (`AKIA…`, `sk_live_`,
  `pk_live_`, `-----BEGIN PRIVATE KEY-----`, and `key=…` / `secret=…` / `token=…`
  assignments) before anything is persisted.
- **Finding lifecycle** — dedupe, status management (`PATCH /findings/{id}`) and a
  per-finding **audit trail**.
- **Reports** — per-scan or per-project HTML/PDF download.
- **Hardened intake** — archive uploads are guarded against zip-bombs and path
  traversal (size / file-count / compression-ratio / single-file limits).
- **Resilient** — interrupted scans are recovered on startup; engines degrade
  gracefully (e.g. on rate limits) instead of aborting the whole run.

---

## Stack

| Layer | Tech |
|---|---|
| Backend | FastAPI + SQLModel (SQLite), routers under `src/api/` |
| Dashboard | Vanilla JS static app under `src/dashboard/` (no build step) |
| Scanners | `bandit`, `opengrep`/`semgrep`, `trivy`, `gitleaks`, `zap` via `src/scanners/` |
| DAST client | ZAP API bridge in `src/dast/` |
| Integrations | Bitbucket REST client + diff parser in `src/integrations/` |
| Tests | pytest + pytest-asyncio (`tests/`) |

---

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# run scans on code pulled from Bitbucket (optional: scan a PR diff)
BITBUCKET_ACCESS_TOKEN=xxx BITBUCKET_WORKSPACE=acme \
  .venv/bin/uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --no-server-header

# or, self-contained: use the dashboard's Upload → Scan (source ZIP) path
```

Run the test suite:

```bash
.venv/bin/pytest
```

Scanners must be installed and on `PATH` (or pointed at via `SCP_*_BIN`). Engine
availability and versions are reported at

```text
GET /api/scanners/status
```

---

## Configuration (environment)

All settings are read from the environment (see `.env.example` for the full list).
Key ones:

| Variable | Purpose | Default |
|---|---|---|
| `SCP_DATABASE_URL` | SQLite URL | `sqlite:///./data/controlplane.db` |
| `SCP_AUTH_USER` / `SCP_AUTH_PASS` | **Optional** HTTP Basic auth (see Security) | *off* |
| `BITBUCKET_ACCESS_TOKEN` / `BITBUCKET_WORKSPACE` | Bitbucket intake credentials | *empty* |
| `SCP_ZAP_API_URL` / `SCP_ZAP_API_KEY` | ZAP (DAST) bridge | `http://127.0.0.1:8080` / *empty* |
| `SCP_MAX_CONCURRENT_ENGINES` / `SCP_MAX_CONCURRENT_SCANS` | parallelism | `4` / `4` |
| `SCP_MAX_UPLOAD_BYTES` / `SCP_MAX_EXPANDED_BYTES` | upload / expanded size caps | `100 MB` / `500 MB` |
| `SCP_MAX_FILES` / `SCP_MAX_FILE_BYTES` | archive file caps | `20000` / `50 MB` |
| `SCP_MAX_COMPRESSION_RATIO` | zip-bomb guard | `100` |
| `SCP_RULES_PACK_DIR` | local rule pack dir | `rules/opengrep-rules` |
| `SCP_TRIVY_SEVERITY` / `SCP_TRIVY_IGNORE_UNFIXED` | Trivy tuning | `CRITICAL,HIGH,MEDIUM` / *off* |

---

## Project layout

```
src/
  api/          FastAPI app + routers (projects, scans, findings, bitbucket,
                reports, uploads) + database + security middleware
  dashboard/    vanilla-JS frontend (index, projects, upload, CSS, JS)
  scanners/     engine adapters (bandit/opengrep/trivy/gitleaks), executor,
                orchestrator, evidence capture + redaction, availability
  dast/         ZAP API client
  integrations/ Bitbucket client + PR diff parser
  reporting/    HTML/PDF report generation
  config.py     centralized env config (validated)
data/           SQLite DB + generated reports       (gitignored)
scan_work/      per-scan working directories        (gitignored)
rules/          bundled OpenGrep rule pack (vendored)
fixtures/       test fixtures: pr-diff.txt, a nested test repo, a vuln app
tests/          pytest suite
```

`data/`, `scan_work/`, and the live `.env` are runtime artifacts and **gitignored —
never committed**.

---

## API surface

Public (always available):

```
GET /api/health                  service + version
GET /api/scanners/status         engine availability + versions
```

Intake:

```
POST /api/projects               create a project
POST /api/projects/{id}/targets  attach a target
POST /api/uploads/scan           scan an uploaded source ZIP
POST /api/uploads/dast           scan an uploaded DAST target
GET  /api/projects               list projects
GET  /api/projects/{id}          project detail
```

Scans & findings:

```
POST /api/scans                  kick off a scan (Bitbucket repo/branch or PR diff)
GET  /api/scans                  list scans
GET  /api/scans/{id}             scan detail
GET  /api/scans/{id}/events      live scan events
GET  /api/findings               list findings
GET  /api/findings/{id}          finding detail
PATCH /api/findings/{id}         update finding status/metadata
GET  /api/findings/{id}/audit    finding audit trail
```

Bitbucket (workspace-scoped read):

```
GET /api/bitbucket/{workspace}/repos
GET /api/bitbucket/{workspace}/{repo}/branches
GET /api/bitbucket/{workspace}/{repo}/pullrequests
```

Reports:

```
POST /api/reports/scan/{scan_id}        generate a scan report
POST /api/reports/project/{project_id}  generate a project report
GET  /api/reports/scan/{scan_id}/download
GET  /api/reports/project/{project_id}/download
```

---

## Security posture

**This is hardening-in-progress** and is reviewed against OWASP. Current state:

| Area | Status |
|---|---|
| **AuthN/AuthZ** | Optional **HTTP Basic auth** via `SCP_AUTH_USER` / `SCP_AUTH_PASS` middleware covering the API *and* the dashboard. Partial config **fails closed** (raises rather than silently running open). `/api/health` stays public for observability. |
| **Security headers** | CSP (self + inline for the vanilla-JS dashboard), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy` (no camera/mic/geo/payment/usb). |
| **Injection** | SQLModel/ORM parameterization; input validation in routers; no raw SQL string building. |
| **Secrets handling** | `.env` gitignored; `gitleaks` is a first-class scanner; evidence capture **redacts credential patterns** before persistence. |
| **Upload hardening** | Zip-bomb guards (expanded-size, file-count, compression-ratio caps) + path-traversal protection. |
| **Dependencies** | `>=` ranges in `requirements.txt` — **run `uvx pip-audit -r requirements.txt` and pin with `pip freeze` before any prod deploy.** |
| **XSS** | Dashboard is vanilla JS; dynamic HTML uses escaping — keep escaping in mind when extending it. |
| **Binding** | An internal tool — run on trusted networks / behind auth only; don't expose to the public internet. |

### ⚠️ Before you expose it

- **Enable auth**: set both `SCP_AUTH_USER` and `SCP_AUTH_PASS` (the middleware
  intentionally fails closed if only one is set).
- **Pin dependencies** and run `pip-audit`.
- **Physical access control**: bind to a trusted interface, use TLS in front of it
  (e.g. a reverse proxy / tunnel), and restrict who can reach it.
- Engines that aren't installed simply report unavailable and are skipped — they
  never crash the platform.

---

## Development

```bash
# backend
.venv/bin/uvicorn src.api.main:app --reload

# tests
.venv/bin/pytest
```

### Adding a scanner engine

Implement a subclass of `src/scanners/base.py:Scanner`, register its adapter and
`ENGINE_SOURCE_TYPE` in `src/scanners/orchestrator.py`, and add a
`SCP_*_BIN`-style override in `src/config.py`. See the bundled adapters for the
contract (availability check, `run`, evidence, error taxonomy).

---

## License / Disclaimer

For **authorized security work on systems you own or are contracted to assess**.
The operator is responsible for ensuring they have permission to scan every
target. No warranty is provided. Do not use this tool against systems you lack
written authorization to test.
