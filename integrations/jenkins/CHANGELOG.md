# Changelog

## 2026-10-07

- No PDF report: a scan produces the SAST report as .docx only. `security-report.pdf` is no longer built, archived
  or committed to the reports repository, and one left there by an earlier scan is removed at the next scan.

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
