# Changelog

## 2026-10-20

- Two secret-scanning false positives are no longer reported. A CKEditor 5 license key (an ES256 JWT naming
  `proxy-event.ckeditor.com`, shipped in the client by design) was flagged as `jwt`, including where Strapi
  stores it in a content-type `schema.json` and in the generated `types/generated/*.d.ts`; a kebab-case
  content slug (e.g. `2024-year-end-event`) was flagged as `generic-api-key`. Both are now allowlisted in the
  built-in secret defaults. The cuts are narrow: a JWT without CKEditor's marker and a mixed-case or
  high-entropy value are still reported, and dedicated token rules (AWS, Slack, GitHub, ...) are untouched.
  Takes effect with the next scan after the SDT checkout is updated (no pipeline library change).

## 2026-10-20

- Deeper AI review of code-security findings, to cut false positives a shallow read misses (e.g. a Vue `v-html`
  whose value is sanitised first). The default model is now `gpt-6.1-sol`; the code shown to the model grew
  (64 lines of surrounding code, up from 40; the enclosing function up to 200 lines; more related lines from
  elsewhere in the file), and up to 8 occurrences per rule are reviewed. `SDT_CODEX_REASONING`
  (`minimal`..`max`, default `medium`) pins the reasoning depth; `medium` keeps a single call under the
  per-call timeout (at `high`/`max` a deep call could time out and stall the review), and `inherit` uses the codex config. Remembered verdicts from
  the previous, shallower context are re-asked once. The review stays advisory: it never changes a SonarQube
  status or an SDT verdict. A deeper review is slower, so raise `SDT_CODEX_BUDGET` if the step reports it
  stopped on the time budget.

## 2026-10-19

- A decision made in SonarQube now shows in the SAST report for every kind of finding, not only for code
  hotspots. A package or configuration check marked Safe, Accepted or False positive still read Open and still
  counted under Needs a Decision; a secret or code issue marked Accepted or False positive was not read at all.
  Packages and configuration checks now have a Status column; a decided secret says "Decided in SonarQube"
  instead of asking for rotation; Fix First and the Review Notes list only what is still open. A package counts
  as decided once all its advisories are. Takes effect with the next scan after the SDT checkout is updated
  (no pipeline library change).

- "Changes Since Previous Scan" in the SAST report now counts SonarQube's own findings. It compared only SDT's
  findings (OpenGrep, Gitleaks, Trivy), so a commit that fixed ten SonarQube hotspots showed 0 fixed, and a report
  listing them showed 0 still open. Each report now writes what it lists (`report-state.json`, digests only) to
  the history directory, and the next report compares with that. Columns: New, Fixed, Still Present (New plus
  Still Present equals the findings the report lists; a hotspot marked Safe is still present). The previous scan
  is named with its commit. The first report after the update has no comparison yet; the one after it does.
  Needs the SDT checkout updated and the pipeline library cache cleared.

## 2026-10-13

- Pre-commit check on the developer's machine (in the SDT repository; nothing changes in Jenkins). `sdt scan
  --staged` existed but read the whole working tree, reported every old weakness in a touched file, named no
  file or line and left its reports in the working tree. It now reads only the staged files, reports what is
  on the lines the commit adds, and prints file, line, rule and what to do. A commit takes 3 to 4 s whatever
  the size of the repository (2.3 to 4.6 s measured). `sdt hook install` sets it up in a repository;
  `.pre-commit-hooks.yaml` serves teams that use the pre-commit framework. It checks secrets and code rules;
  dependencies and SonarQube's own analysers stay with the scan of the pull request, which remains the gate.
  `sdt` now also compiles for Windows; it has not been run there. Set-up, coverage and limits: SDT's
  `docs/local-hook.md`.

## 2026-10-08

- Rule pack wave 3 (in the SDT repository; a scan uses it once the SDT checkout is updated). The code rules
  found 11 of 34 planted weaknesses and scored 5% on OWASP Benchmark; with the added upstream folders, PHP
  rules and three rules of our own they find 33 of 34 and score 68%. Fifteen upstream rules are left out
  because they cost more scan time or noise than they found. Expect more code findings, most of all in PHP
  repositories, and a code scan up to about 1.4 times as long on repositories with much JavaScript. Until
  SonarQube is restarted and `install/sonar/setup-sonar.sh` has run again, findings of the new rules arrive as
  external issues. Details and how to measure: SDT's `docs/detection.md`.
- Every scan is about 20 seconds shorter. The code scanner loaded its rule files one by one, which took 18 s per
  scan whatever the size of the repository; SDT now hands it the same rules as one file (2.5 s, identical
  findings, checked on eight repositories). The plan in `sdt plan` still lists every rule file and shows the
  command line that runs as `execArgs`. `SDT_OPENGREP_MERGE_RULES=0` loads the files one by one again. Tool
  versions are looked up while the scanners run, and SonarQube's import is asked for every second at first.
  Needs the SDT checkout updated (`install/update-sdt.sh`).

## 2026-10-07

- A scan no longer hangs on a committed JavaScript bundle. Minified and generated files are left out of the code
  scan by their content (not only `*.min.js`), the coverage notes say how many, and `run-manifest.json` lists them.
  Findings that were reported inside such files disappear with the next scan. `SDT_SCAN_GENERATED_FILES=1` keeps
  the old behaviour.
- A scanner that reaches its time limit is stopped with all its child processes. Before, only the launcher was
  stopped: the engine kept running and the build waited for it until someone aborted it.
- The code scanner uses at most four cores: on a 14-thread machine it was as fast or faster with 4 than with all
  of them, on half the CPU. `SDT_SCAN_THREADS` and `SDT_SCAN_NICE` cap the cores and the priority of one whole
  scan, for two scans on a small agent (4 cores: two executors and `SDT_SCAN_THREADS=2`).
- `out/timings.tsv`: seconds per step of every scan (wait, clone, scanners, SonarQube, AI review, report).
- The clone may take 30 minutes (`SDT_CLONE_MINUTES`) instead of the git plugin's 10: a repository with a large
  binary in its history could not be scanned at all.
- No PDF report: a scan produces the SAST report as .docx only. `security-report.pdf` is no longer built, archived
  or committed to the reports repository, and one left there by an earlier scan is removed at the next scan.
- Java repositories scan once, not twice, while Maven Central is blocking the machine: the first scan that meets
  the block (429) notes it, and for `SDT_REGISTRY_BLOCK_MINUTES` (30) later Java scans read dependencies from the
  repository's own files straight away. The report's coverage section says so.
- Each scanner's time limit can be set in the scan configuration (`scanners.<name>.timeout`). The fleet
  configuration gives the secret scan 30 minutes, because the full history of a large repository took longer than
  the fixed 10 and its findings were lost. Needs the SDT checkout updated (`install/update-sdt.sh`).

## 2026-10-06

- On-demand scans run side by side. Scans of the same repository wait for each other (`lock`, Lockable
  Resources plugin); without the plugin they are not kept apart and the build log says so.
- Pull-request scans can comment on the Bitbucket Cloud pull request (`SDT_BITBUCKET_API_CREDENTIALS`): passed or
  failed, what the pull request adds, and the SAST report. A later scan updates the same comment.
- Reports repository (`SDT_REPORTS_REPO`): every scan commits `report.md` and the .docx to one repository that
  developers can read; the pull-request comment links it.

## 2026-09-30

- `sdtScan` / `sdtFleetScan` shared-library steps, scanner image, SonarQube profile and quality-gate setup,
  PR and nightly jobs, pre-commit secret hook.
- SAST report (.docx) per scan: code security first, grouped secrets, dependencies, Fix First, trend
  (`SDT_HISTORY_DIR`), coverage gaps, Bitbucket links at the scanned commit, redaction of every line.
- Advisory per code finding: deterministic rules by default; optional Codex review (`SDT_CODEX_*`), bounded
  by per-call timeout, run budget and a failure stop.
- Dart: `pub get` judged by exit code, `dart analyze` report handed to sonar-flutter (MANUAL mode),
  zero-length diagnostics fixed so the plugin cannot abort the upload, unresolved-import flood guard.
- `install/sonar/rotate-token.sh`, `install/jenkins/create-api-token.sh`, `scripts/regenerate-reports.sh`.
