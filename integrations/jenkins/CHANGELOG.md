# Changelog

## 2026-10-07

- A scan no longer hangs on a committed JavaScript bundle. Minified and generated files are left out of the code
  scan by their content (not only `*.min.js`), the coverage notes say how many, and `run-manifest.json` lists them.
  Findings that were reported inside such files disappear with the next scan. `SDT_SCAN_GENERATED_FILES=1` keeps
  the old behaviour.
- A scanner that reaches its time limit is stopped with all its child processes. Before, only the launcher was
  stopped: the engine kept running and the build waited for it until someone aborted it.
- `SDT_SCAN_THREADS` and `SDT_SCAN_NICE`: cap the cores and the priority of one scan, for two scans on a small agent.
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
