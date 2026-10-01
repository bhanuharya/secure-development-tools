# Jenkins + SonarQube integration

Jenkins shared library for **SDT**: scan any Bitbucket repository or
pull request, publish every security finding into SonarQube as a native **Vulnerability** or
**Security Hotspot**, and produce the SAST report (.docx), technical PDF, Excel register, SBOM and
the fleet review history.

Paths in this README are relative to `integrations/jenkins/` unless they start with that prefix.
Your workspace name, SonarQube URL and credentials live in Jenkins configuration, not in this
repository; keep your real `config/repos.txt` in a private fork or point `reposFile` elsewhere.

## What happens in one scan

```
Bitbucket (full history) ─► sdt scan ─► findings.json ─┬─► sonar-scanner + sonar-opengrep-dart ─► SonarQube
                             opengrep · gitleaks · trivy │     OpenGrep rules → Vulnerability / Hotspot (CWE/OWASP)
  dart analyze (Flutter) ───────────────────────────────┤     secrets → Vulnerability (history-only: on the project)
  trivy SBOM (CycloneDX) ──► artifact                   │     dependency CVEs → Vulnerability (unreachable → Hotspot)
                                                        │     quality gate "SDT Security" (new code)
                                                        └─► reports: SAST Report (.docx) · PDF · Excel
                                                            fleet store ◄── review decisions synced back from SonarQube
```

| Piece | Where |
|---|---|
| Jenkins steps `sdtScan`, `sdtFleetScan` | `vars/` (a Jenkins shared library) |
| The scan and report logic (plain bash, runnable outside Jenkins) | `resources/sdt/scan.sh`, `resources/sdt/reports.sh` |
| Job definitions | `jobs/*.Jenkinsfile` |
| Scanner image (sdt, opengrep, gitleaks, trivy, sonar-scanner, Flutter, Python) | `docker/Dockerfile` |
| SonarQube profiles + quality gate | `install/sonar/setup-sonar.sh` |
| Developer pre-commit secret scan | `hooks/.pre-commit-config.yaml` |
| Repositories for the nightly fleet scan | `config/repos.txt` |

SDT's own tools (`sdt_to_docx.py`, `sdt_sonar_sync.py`, `sdt_fleet_ingest.py`, …) live in the SDT repository
and are copied into the scanner image.

## Install

### 1. SonarQube

1. Plugins (`extensions/plugins/`), then restart SonarQube:
   - [sonar-opengrep-dart](https://github.com/bhanuharya/sonar-opengrep-dart/releases): native OpenGrep, secret and dependency rules
   - [sonar-flutter](https://github.com/insideapp-oss/sonar-flutter/releases) 0.5.2: the `dart` language
   - Community Edition only: [community branch plugin](https://github.com/mc1arke/sonarqube-community-branch-plugin)
     (branches and pull requests; follow its javaagent instructions). Developer Edition and above have this built in.
2. `conf/sonar.properties`, so every SDT rule is published, not just Dart:
   ```properties
   sonar.opengrep.languages=*
   sonar.opengrep.rules.directories=/opt/sdt-rules/opengrep-rules
   ```
   Copy SDT's `rules/opengrep-rules` to that directory (the same version the scanner image carries), then restart.
3. Profiles and quality gate (re-runnable; admin token):
   ```bash
   SONAR_HOST_URL=https://sonar.example.com SONAR_TOKEN=... install/sonar/setup-sonar.sh
   ```
4. Create a user or token for Jenkins with **Execute Analysis** (and **Browse** for the report).

### 2. Scanner image

```bash
# from the repository root
docker buildx build -f integrations/jenkins/docker/Dockerfile --build-context sdt=. \
  -t <registry>/appsec/sdt-scanner:<version> integrations/jenkins/docker/ && docker push <registry>/appsec/sdt-scanner:<version>
```

No Docker on the agents? Install the same tools at the versions in the Dockerfile, leave `SDT_IMAGE` empty,
and set `SDT_HOME` (and `FLUTTER_HOME`) in the agent's environment.

### 3. Jenkins

1. Plugins: `install/jenkins/plugins.txt`.
2. Credentials (Manage Jenkins → Credentials):
   | id | kind | content |
   |---|---|---|
   | `sdt-sonar-token` | Secret text | the SonarQube analysis token |
   | `sdt-bitbucket-ssh` | SSH username with private key | a read-only Bitbucket access key for the workspace |
3. Global properties (Manage Jenkins → System → Environment variables):
   | name | example |
   |---|---|
   | `SDT_SONAR_URL` | `https://sonar.example.com` |
   | `SDT_WORKSPACE` | `my-workspace` |
   | `SDT_IMAGE` | `<registry>/appsec/sdt-scanner:<version>` |
   | `SDT_AGENT_LABEL` | `docker` (or empty) |
   | `SDT_FLEET_DATABASE` | `postgresql+psycopg://sdt@db/sdt` (optional: review history) |
4. Global Pipeline Libraries: name `sdt-pipeline`, the secure-development-tools repository,
   **Library Path** `integrations/jenkins/`, default version a tag (for example `v1.0.0`).
5. Jobs: *Pipeline script from SCM* → the secure-development-tools repository → script path:
   - `integrations/jenkins/jobs/sonarqube-scanner.Jenkinsfile`: on-demand, same parameters as the current job
   - `integrations/jenkins/jobs/pull-request.Jenkinsfile`: per PR, quality gate enforced
   - `integrations/jenkins/jobs/nightly-fleet.Jenkinsfile`: nightly, repositories from `config/repos.txt`

### 4. Check it

Run `sonarqube-scanner` for one repository. Expect, in order: `SonarQube import confirmed`,
`quality gate: OK|ERROR`, and in the build artifacts `SAST Report - <repo>.docx`, `security-report.pdf`,
`fleet-findings.xlsx`, `sbom.cdx.json`, `findings.sarif`.

## The SAST report

Every scan attaches `SAST Report - <repo>.docx` to the build (full description in SDT's `docs/sast-report.md`):

* **Cover**: logo (optional, supplied locally), scanners, totals, coverage gaps, executive summary, changes since the previous scan, contents.
* **Fix First**: confirmed real issues, secrets still in the code, open Critical/High vulnerabilities, fixable packages.
* **1. Code Security** first: per rule, every finding with file, line, redacted code excerpt and an **Advisory**
  (assessment, evidence, what to check, what to do). Rules with more than 10 findings are laid out file by file.
* **2. Secret Leaks** grouped by type and file; **3. Dependencies & Configuration** with one upgrade target per package.
* File and line links open **Bitbucket at the scanned commit** (`/src/<commit>/<path>#lines-N`), so the mobile team can
  use the report without SonarQube. No secret value is ever printed.

After changing the report tool, rebuild reports from finished builds without rescanning:
`scripts/regenerate-reports.sh <build numbers>` (settings in the script header).

## Optional: AI-assisted review (Codex)

When the `codex` CLI is on the agent (or `SDT_CODEX_BIN` points to it) and is logged in, every scan adds
an **advisory** review of the code-security findings to the SAST report: per occurrence, "likely real",
"likely false positive" or "needs context", with a reason that cites the code. It never changes a SonarQube
status or an SDT verdict, and secret findings and secret-looking values are never sent.

| Setting | Default | Meaning |
|---|---|---|
| `SDT_CODEX_MODEL` | `gpt-6-luna` | model Codex uses |
| `SDT_CODEX_TIMEOUT` | `120` | seconds per call |
| `SDT_CODEX_BUDGET` | `600` | seconds for the whole review; the step is also wrapped in `timeout` |
| `SDT_AI_TRIAGE` | `1` | `0` turns the review off |

Without Codex every code finding still gets a **deterministic** advisory: fixed per-rule checks (what to confirm
before marking Safe, what to fix), and a conclusion only on strong signals in the flagged line (test code, a log
of static text, an XML namespace URL, a PIN/password/token variable in a log). Same input, same report.

Set `SDT_HISTORY_DIR` to a persistent directory to add "Changes Since Previous Scan" (new / fixed / still open).

It stops after two consecutive failed calls (wrong model, auth, outage) instead of spending more. Without Codex,
the report is produced exactly as before. Check with your data policy that sending code to Codex is allowed.

## When prod differs

| Difference | What to change |
|---|---|
| Agents cannot run Docker | `SDT_IMAGE=` (empty) and install the tools; the scripts only need them on `PATH` |
| Kubernetes agents | wrap `sdtScan` in a `podTemplate` with the scanner image as the default container; `SDT_IMAGE=` |
| HTTP proxy | set `HTTPS_PROXY`/`NO_PROXY` on the agent; trivy needs its DB (or run it `--offline` with a mirrored DB) |
| SonarQube Developer+ edition | skip the community branch plugin; nothing else changes |
| Bitbucket Server/Data Center | change the clone URL and `SCOPE_URL` in `vars/sdtScan.groovy` (one place each) |
| Different credential ids | pass `sonarCredentials:` / `gitCredentials:` to `sdtScan`, or set `SDT_SONAR_CREDENTIALS` / `SDT_GIT_CREDENTIALS` |
| Main branch not `main`/`master` | `MAIN_BRANCHES` in the agent environment (space-separated) |

## Operating it

- **Reviews happen in SonarQube.** Mark hotspots Safe/Fixed/Acknowledged and issues False positive/Accepted there;
  every scan copies those decisions into the fleet store (`sdt_sonar_sync.py`), where accepted risks get a 90-day
  review deadline and the audit trail lives.
- **Secrets in git history** show as project-level Vulnerabilities (`sdt:secret-in-history`). Rotate the credential,
  then mark the issue *Accepted* with the rotation reference as comment.
- **Noisy rules:** `python3 tools/sdt_rule_precision.py --database $SDT_FLEET_DATABASE` in SDT lists precision per
  rule from those reviews and says which to demote to Hotspot or disable.
- **Token rotation:** `install/sonar/rotate-token.sh` (new token, verified, old one revoked), then update the `sdt-sonar-token` credential.
- **Jenkins API token** for automation: `install/jenkins/create-api-token.sh` (asks for your password, never prints the token).
- **Upgrades:** bump versions in `docker/Dockerfile`, rebuild, tag the library; roll back by pinning the previous tag.
