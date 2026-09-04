# Secure Development Tools (`sdt`)

A local-first, provider-agnostic **security scanning runtime** for repositories
and delivery pipelines (PRD `Secure_Development_Tools_PRD_v0.1.docx`). One
deterministic engine runs locally or inside any CI runner: it resolves a
provider-neutral context, plans immutable scanner tasks, executes
OpenGrep/Gitleaks/Trivy adapters, normalizes canonical findings, evaluates
deterministic policy with baselines and expiring exceptions, and always
finalizes `findings.json` + `findings.sarif` + `run-manifest.json` — even on
policy failure. Secrets are redacted everywhere; AI is disabled by default
and can never change a verdict.

```bash
go build -o sdt ./cmd/sdt
./sdt init --dry-run
./sdt doctor            # tools, rules, git history, writable paths
./sdt plan --profile pr --base origin/main
./sdt scan --profile pr --base origin/main --output reports --cache .cache/sdt
echo $?  # 0 passed | 1 policy_failed | 2 invalid_input | 3 execution_failed | 4 inconclusive | 5 internal_error
```

Every flag also reads from the environment, so CI sets values and humans
copy them to reproduce a run bit-for-bit:

| Flag | Env | Default |
|---|---|---|
| `--config` | `SDT_CONFIG` | `.secure-dev.yaml` |
| `--profile` | `SDT_PROFILE` | `pr` |
| `--event` | `SDT_EVENT` | `local` |
| `--base` / `--head` | `SDT_BASE` / `SDT_HEAD` | — / `HEAD` |
| `--image` | `SDT_IMAGE` | — |
| `--output` / `--cache` | `SDT_OUTPUT_DIR` / `SDT_CACHE_DIR` | `reports` / `.cache/sdt` |
| `--offline` | `SDT_OFFLINE` | `false` |

Reports are finalized before the exit code is returned — always retain
`reports/`, even on failure. See `examples/README.md` for the CI contract.

Scanner prerequisites (pinned at release; `sdt doctor` reports status):

```bash
# OpenGrep SAST (v1.29.0 verified)
curl -sL -o ~/.local/bin/opengrep \
  https://github.com/opengrep/opengrep/releases/download/v1.29.0/opengrep_manylinux_x86
chmod +x ~/.local/bin/opengrep
# Gitleaks + Trivy per upstream install docs; sdt honors
# SDT_OPENGREP_BIN / SDT_GITLEAKS_BIN / SDT_TRIVY_BIN overrides.
```

Gitleaks history modes: `pr`/`changed` profiles scan the explicit
`base..head` commit range, `full`/`release` scan `--all` history, and a
missing base visibly falls back to current-tree (`--no-git`). Shallow
clones follow the profile `missingHistory` policy (`fail`/`warn`).

SAST depth: 147 pinned rules (hand-written + curated semgrep-rules subsets
for Python, JS/TS, Go, Kotlin, Java, C, Rust, K8s/GitHub-Actions YAML, AWS
JSON) with cross-function taint (`--taint-intrafile`), per-rule annotated
tests, and manifest hash enforcement — see `rules/NOTICE`,
`docs/rule-precision.md`, and ADR-0007. Terraform provider rules stay out
by design (Trivy owns IaC).

Workflow commands:

```bash
./sdt baseline create --from reports/findings.json   # explicit legacy-debt snapshot
./sdt baseline compare --from reports/findings.json  # new / existing / resolved
./sdt policy test --from reports/findings.json       # re-evaluate saved report
./sdt rules verify                                   # validate + per-rule tests + manifest hashes
./sdt rules propose --from reports/                  # rank repeat findings, draft rule skeletons
# Optional: junit/sbom/vex formats via outputs.formats, provider payloads, advisory explain
./sdt publish --provider github   # needs publish.enabled=true; never rescans
./sdt explain --finding <id>      # needs ai.enabled=true; local-only, advisory
./sdt fix                         # dry-run diff of safe mechanical fixes (never commits)
./sdt fix --apply                 # write working tree, per-file atomic + syntax-checked
./sdt fix --only scp.python.crypto.weak-md5 --patch fix.diff
```

Fast pre-commit path and supply chain:

```bash
./sdt init --hook                 # install pre-commit hook running scan --staged
./sdt scan --staged               # staged files only (opengrep+gitleaks); trivy deferred to CI
SKIP_SDT=1 git commit ...         # bypass once; CI remains the authoritative gate
```

Add `sbom`/`vex` to `outputs.formats` for `sbom.cdx.json` (merged trivy
CycloneDX inventory) and `vex.cdx.json` (policy-derived exploitability
statements; `not_affected` is never emitted). The full format→artifact map:
`console` (stdout), `json`→`findings.json`, `sarif`→`findings.sarif`,
`manifest`→`run-manifest.json`, `junit`→`policy.junit.xml`,
`sbom`→`sbom.cdx.json`, `vex`→`vex.cdx.json`, plus always-written
`summary.txt`. Defaults are `console, json, sarif, manifest`.

Dependency findings carry `reachability` (`reachable`/`unreachable`/`unknown`,
proven for Go/Python/JS imports; anything doubtful resolves to `unknown`).
Match on it in policy alongside the other dimensions:

```yaml
policy:
  rules:
    - id: block-reachable-critical-deps
      match:
        categories: [dependency-vulnerability]
        severities: [critical]
        baselineStates: [new, unknown]
        reachable: [reachable]   # unknown matches neither value: uncertainty
      action: fail               # can neither trigger nor silence a rule
```

`fix` covers three whitelisted, versioned transforms
(`gha-pin-action/v1`, `py-hashlib-sha256/v1`, `py-yaml-safe-load/v1`):
exact-line rewrites only, secrets never touched, syntax-checked after
apply. Disable a transform generation without renaming it via
`.secure-dev/fix-quarantine.yaml`:

```yaml
disabled: [py-hashlib-sha256/v1]
```

See `.secure-dev.yaml`, `schemas/`, `docs/adr/`, `examples/README.md`, and
`packaging/Dockerfile`. The previous Python control plane remains under
`src/` as reference.

---

## Legacy: Secure SDLC Control Plane (Python, reference)

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
  - **SCA / dependencies** — `trivy` fs vulnerability scanning plus `osv-scanner`
    (Google OSV) for multi-ecosystem lockfile analysis.
  - **IaC misconfiguration** — `checkov` (Terraform, Kubernetes, Dockerfile,
    CloudFormation) plus Trivy's `misconfig` scanner.
  - **Secrets** — `gitleaks`.
  - **DAST** — `zap` (via the OWASP ZAP API).
- **Two intake paths**
  - **Bitbucket** — pick a workspace/repo/branch, optionally a pull-request diff
    (only changed lines are scanned), and run a scan.
  - **Upload** — push a source **ZIP**, scan a **local folder** on the host
    (allowlisted via `SCP_LOCAL_SCAN_ROOTS`), or a **DAST target**
    (auth-protected URL), directly through the dashboard or CLI. DAST targets
    must be **approved** (an audited, server-side step) before any active scan
    runs against them.
- **Evidence with redaction** — findings capture code context (source snippet +
  8 KiB cap), but **every credential-like value is redacted** (`AKIA…`, `sk_live_`,
  `pk_live_`, `-----BEGIN PRIVATE KEY-----`, and `key=…` / `secret=…` / `token=…`
  assignments) before anything is persisted — and **again client-side** when the
  dashboard renders a finding, so secrets/keys never reach the DOM unredacted.
- **Finding drill-down** — click any finding for a detail modal showing the
  vulnerable source snippet with line numbers and flagged-line annotations, plus
  plain-English "what is this / how to fix / references" explanations.
- **Terminal dashboard** — a black, phosphor-green "hacker terminal" UI (CRT
  scanlines, monospace, glow) across the Dashboard, Projects, and Upload screens.
- **Finding lifecycle** — dedupe, status management (`PATCH /findings/{id}`),
  bulk triage (`POST /findings/bulk-status`), and a per-finding **audit trail**.
- **Reports** — per-scan or per-project HTML/PDF download.
- **CLI for humans and bots** — `python -m src.cli` drives the whole platform
  (scans, watch, findings triage, reports) with table output for people and
  `--json` for automation.
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
| Scanners | `bandit`, `opengrep`/`semgrep`, `trivy`, `gitleaks`, `checkov`, `osv-scanner`, `zap` via a central engine registry (`src/scanners/registry.py`) |
| DAST client | ZAP API bridge in `src/dast/` |
| Integrations | Bitbucket REST client + diff parser in `src/integrations/` |
| CLI | httpx-based bot/human client in `src/cli.py` (`python -m src.cli`) |
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

### CLI

```bash
export SCP_URL=http://127.0.0.1:8000
export SCP_API_TOKEN=...          # or SCP_AUTH_USER / SCP_AUTH_PASS

.venv/bin/python -m src.cli status
.venv/bin/python -m src.cli projects list
.venv/bin/python -m src.cli scan zip app.zip --preset full --watch
.venv/bin/python -m src.cli scan folder /srv/repos/my-app --preset iac
.venv/bin/python -m src.cli findings list --severity-gte high --status new
.venv/bin/python -m src.cli findings bulk-triage 12 13 14 false_positive --reason "fp"
.venv/bin/python -m src.cli report scan 42 -o report.pdf
```

Every command accepts `--json` for machine-readable output, so bots can drive
the entire platform without scraping HTML.

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
| `SCP_API_TOKEN` | **Optional** Bearer token for bots/automation (accepted instead of Basic) | *off* |
| `SCP_LOCAL_SCAN_ROOTS` | Allowlisted roots for local folder scans (`os.pathsep`-separated); empty = disabled | *empty* |
| `SCP_DAST_ALLOWED_HOSTS` | Allowlisted DAST target hosts (comma-separated, `*.suffix` wildcards); empty = all hosts allowed | *empty* |
| `SCP_SECRET_KEY` | Encryption key (Fernet key or passphrase) for DAST target credentials at rest; required to store passwords | *empty* |
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
POST /api/uploads/folder         scan a local folder (allowlisted roots only)
POST /api/uploads/dast           register a DAST target (does NOT scan; see Targets)
GET  /api/projects               list projects
GET  /api/projects/{id}          project detail
```

Targets (DAST approval is a separate, audited step — never a client flag):

```
POST /api/targets/{id}/approve   approve a target for active scanning
                                 (production targets require production_ack=true)
POST /api/targets/{id}/revoke    withdraw approval
GET  /api/targets/{id}/audit     approval audit trail
```

Scans & findings:

```
POST /api/scans                  kick off a scan (Bitbucket repo/branch or PR diff)
GET  /api/scans                  list scans (?offset=&limit=; X-Total-Count header)
GET  /api/scans/{id}             scan detail
GET  /api/scans/{id}/events      live scan events
GET  /api/findings               list findings (filters, ?severity_gte=, ?offset=,
                                 ?include_evidence=; ordered by true severity rank;
                                 X-Total-Count header; evidence omitted by default)
GET  /api/findings/{id}          finding detail
PATCH /api/findings/{id}         update finding status/metadata
POST /api/findings/bulk-status   batch triage {ids, status, reason}
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
| **AuthN/AuthZ** | Optional **HTTP Basic auth** via `SCP_AUTH_USER` / `SCP_AUTH_PASS`, plus an optional **Bearer API token** (`SCP_API_TOKEN`) for bots — middleware covers the API *and* the dashboard. Partial config **fails closed** (raises rather than silently running open). `/api/health` stays public for observability. |
| **CSRF** | Cross-site state-changing requests are rejected (`Sec-Fetch-Site`, with an `Origin` fallback) — including the multipart upload endpoints, which browsers would otherwise send cross-site with ambient Basic credentials. |
| **Brute force** | Failed auth attempts are throttled per client IP (lockout after repeated failures, `429` + `Retry-After`). |
| **Security headers** | CSP (self + inline for the vanilla-JS dashboard), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy` (no camera/mic/geo/payment/usb). |
| **Injection** | SQLModel/ORM parameterization; input validation in routers; no raw SQL string building. |
| **Secrets handling** | `.env` gitignored; `gitleaks` is a first-class scanner; evidence capture **redacts credential patterns** before persistence (AWS/GitHub/Slack/Stripe/Google/GitLab/OpenAI-style tokens, JWTs, private keys, `Bearer`/`Basic` headers, and `key=`/`secret=`/`token=`-style assignments incl. composed names like `aws_secret_access_key`), and the dashboard **masks the same families a second time in the browser** before rendering (defense-in-depth). |
| **Upload hardening** | Zip-bomb guards (expanded-size, file-count, compression-ratio caps) + path-traversal protection. Local folder scans are restricted to operator-allowlisted roots (`SCP_LOCAL_SCAN_ROOTS`) and copied — never symlinked — into the scan workspace. |
| **DAST gating** | Registering a target never launches a scan. Approval is a **separate server-side, audited action** (`POST /api/targets/{id}/approve`; production targets additionally require `production_ack=true`); there is no client-supplied confirmation flag. Target hosts can be restricted with `SCP_DAST_ALLOWED_HOSTS` (exact names or `*.suffix` wildcards; empty = all hosts). DAST target credentials are **encrypted at rest** with `SCP_SECRET_KEY` (storing a password without a key fails closed). |
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

Implement a subclass of `src/scanners/base.py:Scanner`, then register a single
`EngineSpec` in `src/scanners/registry.py` (name, source type, build/skip/status
hooks) and add a `SCP_*_BIN`-style override in `src/config.py`. The orchestrator,
engine validation, and `/api/scanners/status` all derive from the registry — no
other files need editing. See the bundled adapters for the contract (availability
check, `run`, evidence, error taxonomy).

---

## License / Disclaimer

For **authorized security work on systems you own or are contracted to assess**.
The operator is responsible for ensuring they have permission to scan every
target. No warranty is provided. Do not use this tool against systems you lack
written authorization to test.
