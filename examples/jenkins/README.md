# Jenkins: SDT sidecar next to free Sonar (DevOps handoff)

Pipeline order (SDT runs BEFORE Sonar — the import file must exist at analysis):
`checkout (full history)` → `2a SDT scan` → `2b Sonar with import` → `2c insights POST (optional)` → `archive` → `Clean Workspace`.

| File | Use |
|---|---|
| `sdt-jenkins.sh` | Worker: `doctor → plan → scan → PDF → sonar-external.json → insights payload`. Always writes `reports/`. |
| `Jenkinsfile.sdt-scanner` | Standalone parameterized job (reponame/branch/codebase + `SDT_STRICT_MODE`). No shared-lib change. |
| `vars/sdtScan.groovy` | Shared-lib step for your library (`vars/`). Reusable gate + Warnings NG. |
| `tools/sdt_to_sonar.py` | Converter: `findings.json → sonar-external.json` (latest generic schema: works on 10.7, mandatory-safe past 10.8). |
| `tools/sdt_knowledge.py` | Shared, stdlib-only guidance + safe snippet reader (imported by the PDF tool; no network/AI). |

## Agent prep (once)

```bash
git clone <secure-development-tools> /opt/sdt
cd /opt/sdt && go build -o sdt ./cmd/sdt   # Go 1.24+
# plus on PATH: opengrep 1.29.0, gitleaks, trivy
# python3 + reportlab for the PDF: pip install "reportlab>=4.0"
# warm Trivy DB: trivy fs --download-db-only
```

## Gate (advisory-first, strict on demand)

`sdt` exits `0 passed | 1 policy_failed | 2 invalid | 3 exec_failed | 4 inconclusive | 5 internal`.
Default mapping: `1 → UNSTABLE`, `4 → UNSTABLE`, `2/3/5 → FAILURE`.
Flip one boolean for strict: `SDT_STRICT_MODE=true` job param, or `sdtScan(..., strict: true)` → `1 → FAILURE`.
Sonar stage stays untouched.

## Why Sonar shows ~0 while SDT blocks

Free Sonar `Security Hotspots 100% Reviewed / 0 to review` ≠ clean — it lacks
secrets-history (`gitleaks --all`), supply-chain + misconfig (`trivy offline`),
and taint SAST breadth (147 opengrep rules). In our Phase 1 pilot (`full`
scan of a JHipster service) SDT found dozens of findings (secrets + SAST +
deps) where Sonar reported zero hotspots.
Keep Sonar as-is; SDT is the additive depth. Correlate via
`run-manifest.json:{runId,planId,tools[].version}` + `findings.json` fingerprints.

## Findings per persona (no manual copy-paste)

* **Developer (PR author)**: PR triggers the job via webhook (no manual repo/branch/lang
  config; SDT auto-detects languages). Hits land **inline on the PR** once DevOps wires
  the insights POST (`reports/bitbucket-code-insights.json` + Bitbucket token → Code
  Insights API; 50 annotations, blockers first). Fix guidance ships in the finding
  (PDF risk/assess/fix sections); repro any CI hit locally from logged `SDT_*` values.
* **Security**: one dashboard — SDT issues inside Sonar (Issues tab) via
  `-Dsonar.externalIssuesReportPaths=reports/sonar-external.json` (no plugin, works on
  Community/10.7); trend view via Warnings NG on `reports/findings.sarif`; printable
  `security-report.pdf` replaces the ChatGPT copy-paste report; Jenkins exit codes stay
  the enforcement point (external issues don't reliably fail the Sonar Quality Gate).
* **DevOps**: owns job + webhook + Warnings NG + retention + the insights POST credential;
  flips advisory→strict per repo (`SDT_STRICT_MODE` / `strict:true`).
* **Auditor/management**: per-build PDF + manifest digests as evidence.

## Wiring checklist for DevOps

1. Agent prep per README above + `trivy fs --download-db-only` warm.
2. Webhook: Bitbucket → Jenkins job on PR (params auto-filled; keep manual Build with
   Parameters as fallback).
3. Sonar step appends `-Dsonar.externalIssuesReportPaths=reports/sonar-external.json`
   (file is produced in stage 2a, same workspace).
4. Warnings NG plugin installed (worker degrades gracefully without it).
5. Insights POST: `PUT .../commit/{sha}/reports/sdt` + annotations, needs repo-scope
   token; stage 2c no-ops until wired. Target repos need `publish.enabled: true` in
   `.secure-dev.yaml` for the payload step.
6. First green run per repo → `sdt baseline create` to grandfather legacy debt.

## Gotchas from Phase 1 (baked into `sdt-jenkins.sh`)

* Checkout **full history** (`depth: 0`) — shallow + `missingHistory: fail` → exit 4.
* `pr` profile needs a real merge-base; parameterized one-shot scans use `full`.
* Trivy online resolve hits Maven `429`s → worker defaults `TRIVY_OFFLINE_SCAN=true`
  (`SDT_TRIVY_ONLINE=true` opts back into remote resolution; internet is available).
* `Clean Workspace` runs **after** `archiveArtifacts reports/**/*, plan.json`.
