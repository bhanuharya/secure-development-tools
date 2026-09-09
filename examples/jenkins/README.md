# Jenkins: SDT sidecar next to free Sonar (DevOps handoff)

Fits the existing `Security/sonarqube-scanner` shape (`reponame/branch/codebase`
params → checkout → `stage 2 - Sonarqube scan` → `Clean Workspace`):
add **`stage 2b - SDT scan`** after Sonar, archive **before** `Clean Workspace`.

## Files

| File | Use |
|---|---|
| `sdt-jenkins.sh` | Worker: `doctor → plan → scan → offline PDF`, always writes `reports/`. Called by both entries below. |
| `Jenkinsfile.sdt-scanner` | Standalone parameterized job (same params as screenshots + `SDT_STRICT_MODE`). No shared-lib change. |
| `vars/sdtScan.groovy` | Shared-lib step for the DevOps-owned library (`vars/`). Reusable gate. |

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
and taint SAST breadth (147 opengrep rules). Phase 1 on `hotsregistration/full`
found `77 (1 critical/55 high/21 medium, 49 blockers)` where Sonar found none.
Keep Sonar as-is; SDT is the additive depth. Correlate via
`run-manifest.json:{runId,planId,tools[].version}` + `findings.json` fingerprints.

## Gotchas from Phase 1 (baked into `sdt-jenkins.sh`)

* Checkout **full history** (`depth: 0`) — shallow + `missingHistory: fail` → exit 4.
* `pr` profile needs a real merge-base; parameterized one-shot scans use `full`.
* Trivy online resolve hits Maven `429`s → worker defaults `TRIVY_OFFLINE_SCAN=true`
  (`SDT_TRIVY_ONLINE=true` opts back into remote resolution; internet is available).
* `Clean Workspace` runs **after** `archiveArtifacts reports/**/*, plan.json`.
