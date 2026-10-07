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
   On a single machine where the Jenkins user already has a Bitbucket SSH key, set
   `SDT_GIT_CREDENTIALS=none` instead: no credential and no ssh-agent plugin needed.
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
   - `integrations/jenkins/jobs/scan.Jenkinsfile`: on-demand. Pick `scan_type`:
     `branch` scans the whole branch (gate reported); `pull-request` scans only what the PR adds over
     `pr_base`, using the target branch as the baseline (gate enforced).
     For a pull request that is already merged, also give `merge_commit`: the scan compares that
     commit with its first parent. It works for merge and squash commits, not for a fast-forward of several commits.
     Builds of this job run side by side, up to the agent's executors; two scans of the same repository wait
     for each other.
   - `integrations/jenkins/jobs/pull-request.Jenkinsfile`: the same PR scan, for webhook-triggered jobs
   - `integrations/jenkins/jobs/nightly-fleet.Jenkinsfile`: nightly, repositories from `config/repos.txt`

### 4. Production on Docker agents

The scanner is stateless and runs in the image on your existing Docker agents. Three things live outside it:

| What | Where | Setting |
|---|---|---|
| SonarQube | your SonarQube server, with the plugins of step 1 | `SDT_SONAR_URL` |
| Review decisions | a PostgreSQL database the agents can reach | `SDT_FLEET_DATABASE` |
| Scan history, AI verdict memory, Codex login, Trivy database | one volume, mounted at `/var/lib/sdt` | `SDT_DOCKER_ARGS=-v sdt-state:/var/lib/sdt` |

Without the volume a scan still works, but reports have no "changes since previous scan" and the AI review
asks every question again. On several agents use a shared volume (NFS or similar), not a local one.

- **Every setting** is listed with its default in [`config/settings.env.example`](config/settings.env.example).
- **AI review** needs the Codex CLI in the image (`--build-arg CODEX_VERSION=<version>`) and a login in the
  volume (`CODEX_HOME=/var/lib/sdt/codex`). A container has no browser, so sign in where there is one and copy
  the result in: run `codex login` on a workstation, then put that machine's `~/.codex/auth.json` into the volume
  as `codex/auth.json`, owned by uid 1000 and mode 600 (`codex login --with-api-key` reading a key from stdin, or
  `codex login --device-auth`, also work). The file holds that account's sign-in tokens: treat it like a password,
  use a team or service account rather than a person's, and keep the volume writable so Codex can refresh them. Decide first whether code
  excerpts may leave your network; with `SDT_AI_TRIAGE=0` nothing is sent and every other feature still works.
- **Pin versions:** `SDT_IMAGE` to an image tag and the pipeline library to a release tag, so a push to the
  repository never changes a production scan.
- **Check the install** from inside the image before the first job (it changes nothing):
  ```bash
  docker run --rm -v sdt-state:/var/lib/sdt -e SONAR_HOST_URL=https://sonar.example.com -e SONAR_TOKEN \
    -e FLEET_DATABASE=... <image> /opt/sdt/preflight.sh
  ```
  Each line is `OK`, `WARN` (works, a feature is off) or `FAIL` (a scan would break). The Bitbucket check
  needs the SSH key, so it fails in this bare command and passes inside a job.

### 5. Check it
 
Run the on-demand job (`scan_type` = `branch`) for one repository. Expect, in order: `SonarQube import confirmed`,
`quality gate: OK|ERROR`, and in the build artifacts `SAST Report - <repo>.docx`,
`fleet-findings.xlsx`, `sbom.cdx.json`, `findings.sarif`.

## Comment on the pull request

Set `SDT_BITBUCKET_API_CREDENTIALS` to a *Secret text* credential and every pull-request scan leaves one comment
on the Bitbucket Cloud pull request: **PASSED** or **FAILED** (the SonarQube quality gate), the findings the pull
request adds (severity, type, rule, file and line; never a secret value), and links to the SAST report, SonarQube
and the build. A later scan of the same pull request updates that comment. A scan that did not finish says
**NOT COMPLETED**, never passed. A comment that cannot be posted is logged and does not fail the build.

| Token | Scopes | Also set |
|---|---|---|
| Repository, project or workspace **access token** | pull requests: write; repositories: write (for the report) | nothing |
| **API token** of a bot account | the same | `SDT_BITBUCKET_API_USER` = that account's email |

The report is uploaded to the repository's **Downloads** (`SAST Report - <repo> - PR <id>.docx`, replaced by the
next scan) and linked from the comment, because Bitbucket Cloud has no API to attach a file to a comment. Downloads
are readable by everyone who can read the repository, so a repository that is not private never gets the upload:
its comment links the build artifact instead. `SDT_PR_REPORT_UPLOAD=0` turns the upload off everywhere.

### Reports repository

Set `SDT_REPORTS_REPO` to a repository in the workspace (a slug, or `workspace/slug`) and every scan commits its
report there with the same token, which then needs write access to that one repository only:

```
<repo>/branches/<branch>/report.md        + SAST Report.docx
<repo>/pull-requests/<id>/report.md       + SAST Report.docx
```

`report.md` renders in Bitbucket and diffs line by line; each scan overwrites its own folder, so the repository's
history is the history of the findings. The pull-request comment links `report.md` and nothing is uploaded to
Downloads. Everyone who can read the reports repository can read every report in it: use one per team or project
if developers must not see each other's findings.

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
| `SDT_TRIAGE_MEMORY` | `~/.cache/sdt/triage/<project>.json` | remembered verdicts: unchanged code is not asked again |
| `SDT_AI_AUTOCLOSE` | `0` | `1` marks the clearest false positives Safe in SonarQube (see SDT's `docs/sast-report.md`) |
| `SDT_AI_DIFF_REVIEW` | `0` | `1` adds an AI read of each pull request's changed lines (`ai-change-review.md`), advisory only |

Without Codex every code finding still gets a **deterministic** advisory: fixed per-rule checks (what to confirm
before marking Safe, what to fix), and a conclusion only on strong signals in the flagged line (test code, a log
of static text, an XML namespace URL, a PIN/password/token variable in a log). Same input, same report.

Set `SDT_HISTORY_DIR` to a persistent directory to add "Changes Since Previous Scan" (new / fixed / still open). A
branch scanned for the first time is compared with the most recently scanned other branch of the repository, so a
new release branch shows what changed since the previous release.

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
- **A reviewed false positive is not reported again.** With `SDT_FLEET_DATABASE` set, each scan first exports the
  findings reviewers judged false positive on any branch of the repository (`sdt_fleet_exceptions.py`) and applies
  them as exceptions: they stay in `findings.json`, marked, and are left out of SonarQube and the reports. Secrets
  are never excepted this way; see SDT's `docs/false-positives.md`.
- **A review decision holds on every branch.** SonarQube keeps a decision on the branch where it was made, so a
  new release branch would ask again. After each analysis, `sdt_sonar_carry.py` copies Safe / Acknowledged /
  False positive / Accepted decisions from the project's other branches onto the same finding here: same rule,
  same file, same line of code. Each copy is commented with the branch and date it came from. A line that was
  edited is a new finding and is not decided for you. `SONAR_CARRY_DECISIONS=0` turns it off.
- **Test code is analysed as test code.** Paths matching `SONAR_TEST_PATTERNS` (default: `test/`, `tests/`,
  `__tests__/`, `*.test.*`, `*.spec.*`, `*_test.go`, `*_test.dart`) are given to SonarQube as tests, so its security
  rules for application code do not report fixtures. SDT's own scanners still cover them. If a repository has a
  Dockerfile and its `.dockerignore` does not exclude a test directory, the report's coverage notes say so. Set
  `SONAR_TEST_PATTERNS` to empty to analyse everything as application code.
- **Minified and generated files are left out of the code scan.** A committed bundle is recognised by its
  content (20 KB or more, with a line of 5,000 characters or 250 characters per line on average), not by its name.
  The scanner's cross-function analysis does not finish on such a file, and a finding in it could not be fixed
  there. Secret and dependency scanning still read these files. The report's coverage notes give the number, and
  `run-manifest.json` lists the files (`tasks[].skippedFiles`). `SDT_SCAN_GENERATED_FILES=1` scans them after all.
- **A scanner's time limit stops everything the scanner started.** A scanner that runs out of time is stopped
  together with its child processes, the scan reports it as `timeout`, and the build goes on. Limits are set in
  the scan configuration (`scanners.<name>.timeout`).
- **Two scans on a small agent.** By default every scanner uses all cores. `SDT_SCAN_THREADS` caps one scan
  (code scanner, secret scanner, dependency scanner and sonar-scanner's JVM), and `SDT_SCAN_NICE` (0 to 19) lowers
  the priority of everything a scan starts, so other work on the machine goes first. On 4 cores with two
  executors, `SDT_SCAN_THREADS=2` keeps two scans from competing.
- **Where a scan spent its time:** `out/timings.tsv`, archived with the build, has the seconds per step (waiting
  for an agent, clone, each scanner, SonarQube analysis and import, AI review, report, fleet store). The last line
  of the reports stage prints the same.
- **Secrets in git history** show as project-level Vulnerabilities (`sdt:secret-in-history`). Rotate the credential,
  then mark the issue *Accepted* with the rotation reference as comment.
- **Noisy rules:** `python3 tools/sdt_rule_precision.py --database $SDT_FLEET_DATABASE` in SDT lists precision per
  rule from those reviews and says which to demote to Hotspot or disable.
- **Token rotation:** `install/sonar/rotate-token.sh` (new token, verified, old one revoked), then update the `sdt-sonar-token` credential.
- **Jenkins API token** for automation: `install/jenkins/create-api-token.sh` (asks for your password, never prints the token).
- **Updating SDT itself:** keep `SDT_HOME` a separate checkout from the one you develop in, and move it forward
  with `install/update-sdt.sh --home "$SDT_HOME"` (fetch, check out `origin/main`, rebuild the binary). Scans then
  change only when you run it, never because of an unfinished edit.
- **Upgrades:** bump versions in `docker/Dockerfile`, rebuild, tag the library; roll back by pinning the previous tag.
