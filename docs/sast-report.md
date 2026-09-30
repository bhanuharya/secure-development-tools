# SAST report (.docx)

`tools/sdt_to_docx.py` turns one scan of one repository (a branch or a pull request) into a Word report
that developers can act on. It is stdlib-only: the layout, fonts and footer come from
`tools/templates/sast-report.docx`; the logo from `tools/templates/logo.png`.

```bash
SONAR_TOKEN=... python3 tools/sdt_to_docx.py \
  --sonar-url https://sonar.example.com --project-key KEY --branch release/1.0 \
  --findings out/findings.json --src-root source \
  --repository mirae-asset-id/app --commit 2d50829cc3b8 \
  --scope-url https://bitbucket.org/mirae-asset-id/app/branch/release/1.0 \
  --triage triage.json --previous-findings history/findings.json --coverage coverage.txt \
  --out "SAST Report - app.docx"
```

Either source alone works: `--sonar-url` (code findings with their review status and assignee) or
`--findings` (SDT canonical findings). With both, code comes from SonarQube and secrets, dependencies and
configuration come from SDT, which knows commits, versions and reachability.

## What is in it

| Page | Content |
|---|---|
| Cover | Logo, scope link, metadata (scanners, totals, coverage gaps), Executive Summary, Findings Summary, Changes Since Previous Scan, contents (a Word TOC field with clickable entries) |
| Fix First | Ordered to-do list: 1 confirmed real issues, 2 secrets still in the code, 3 other open Critical/High code vulnerabilities, 4 Critical/High packages that have a fix |
| 1. Code Security | Per rule: severity, type, status, assignee, risk, recommendation, then the findings (see layout below) |
| 2. Secret Leaks | Grouped by secret type and file (gitleaks and SonarQube reports of the same file collapse); still-in-code first, Firebase/Google client keys last ("restrict, don't rotate") |
| 3. Dependencies & Configuration | One row per vulnerable package with all its advisories and one **Upgrade To** version (the lowest release that fixes all of them), reachability; Trivy configuration checks |
| Review Notes | Factual notes, then **Coverage**: what the scan could not cover (e.g. Dart lint skipped) and scanners that did not complete |

Every page after the cover has a header (logo, project, scope) and a footer with "Page X of Y"; table
header rows repeat on each page and rows never split. Fonts are Segoe UI / Segoe UI Semibold, headings and
table headers use the Mirae Asset navy (`#003F7E`).

### Code findings layout

* A rule with **10 findings or fewer** (`--group-threshold`): each finding gets a row, a code excerpt and its
  advisory.
* A rule with **more**: a per-file summary (hits, lines, status, advisory outcomes), then every file with every
  finding listed (line, status, assessment, evidence). Nearby lines share one excerpt, so nothing repeats and
  nothing is dropped.
* Excerpts mark flagged lines with `>` and lines the advisory cites as evidence ("at line 92") with `*`.

### Links

File and line cells link to **Bitbucket at the scanned commit** with the lines highlighted
(`/src/<commit>/<path>#lines-80:92`); secrets found only in git history link to the commit they were found in.
The base is derived from `--repository` and `--commit` (or given with `--source-url`). `--link-to sonar` links
to the SonarQube finding instead.

### Secrets are never printed

Every piece of text written to the report, code excerpts included, passes through
`sdt_advisory.redact()` (private keys, AWS/Google/GitHub/Slack/Stripe/Sonar tokens, JWTs, and
`password|secret|token|api_key = "..."` assignments). A test builds a full report around a planted key and
checks it appears nowhere in the file.

## The advisory

Every code finding carries an **Advisory** (purple heading and labels) with fixed wording:

| Assessment | Then |
|---|---|
| False positive - can be marked Safe | Evidence; Before marking Safe, confirm; Record in SonarQube |
| Real issue - fix required | Evidence; Confirm impact; Fix |
| Manual check required | Evidence; Check; Then |

It never changes a SonarQube status or an SDT verdict.

**Deterministic by default** (`tools/sdt_advisory.py`, no model): a fixed per-rule checklist (what to confirm,
what to fix, what to record when Safe), and a conclusion only on strong signals in the flagged line: test or
example code, a log of static text, an XML namespace URL, random values used for UI/notification ids (false
positives), or a PIN/password/token variable interpolated into a log (real issue). Same input, same report.
A generic rule-based check is printed once per rule in the grouped layout.

**Optional model review** (`tools/sdt_triage_codex.py`): when the `codex` CLI is installed and logged in, the
code findings are sent, rule by rule, to Codex (`SDT_CODEX_MODEL`, default `gpt-6-luna`) with the enclosing
function as context. The prompt's main job is ruling out false positives against a six-point checklist; the
answer is an enforced JSON schema (verdict, confidence, evidence, check, fix). Guardrails:

* only code findings are sent, never secret findings, and likely secret values are redacted first;
* read-only sandbox, empty working directory, ephemeral session;
* per-call timeout (`SDT_CODEX_TIMEOUT`, 120 s), whole-run budget (`SDT_CODEX_BUDGET`, 600 s), and a stop after
  two consecutive failed calls;
* without Codex (or with `SDT_AI_TRIAGE=0`) the step is a no-op and the deterministic advisory is used.

Once reviewers decide findings in SonarQube, the cover shows "Advisory accuracy so far: agreed with X of Y".

## Trend and coverage

* `--previous-findings`: the previous scan of the same branch; the report counts new, fixed and still-open
  findings by SDT fingerprint.
* `--coverage`: a text file, one gap per line, written by the pipeline (for example when `flutter pub get`
  fails and Dart lint is skipped). Scanners that did not complete are read from `run-manifest.json`.

## Related tools

| Tool | Purpose |
|---|---|
| `tools/sdt_sonar_sync.py` | Copies review decisions made in SonarQube (Safe, False positive, Accepted, ...) into the fleet store through the one review service; accepted risks get a review deadline |
| `tools/sdt_rule_precision.py` | Per-rule precision from reviewed findings, with keep / demote to Hotspot / disable recommendations |
| `tools/sdt_to_sonar.py --skip-adapter` | Leaves findings that sonar-opengrep-dart imports natively out of the generic external-issue import |
