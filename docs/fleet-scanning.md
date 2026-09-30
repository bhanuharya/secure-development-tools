# Central Bitbucket Cloud scans

`tools/sdt_fleet.py` inventories one workspace and runs the Go `sdt full`
profile on each default branch. It uses full Git history, separate temporary
checkouts and caches, and a permanent artifact directory per fleet run. It
does not write to Bitbucket or to the separate production SonarQube instance.

## One-time setup

1. Build the Go runtime (`go build -o sdt ./cmd/sdt`) and install the pinned
   OpenGrep, Gitleaks, and Trivy binaries. Run `./sdt doctor` locally.
2. Authenticate with Bitbucket in one of two ways:
   - `--transport ssh` (recommended when no workspace token is available):
     a personal SSH key registered under Personal settings → SSH keys, passed
     via `--ssh-key` (default `/home/wishnu/.ssh/bitbucket_sdt`). The key must
     be mode 0600, and the `bitbucket.org` host key must be pinned in
     `~/.ssh/known_hosts` (`ssh-keyscan bitbucket.org >> ~/.ssh/known_hosts`).
     A repository list file supplies the slugs; no API inventory runs.
   - `--transport token` (default): a read-only workspace access token from the
     workspace administrator. Store the token outside the repo.
3. Use the local SonarQube analysis token only if importing into this Ubuntu
   SonarQube. The runner defaults to the local scanner and token-file paths;
   override both flags on another host.
4. Warm the Trivy databases once before a fleet run so repository scans do not
   race on downloads: `trivy image --download-db-only` and
   `trivy image --download-java-db-only`.

```bash
python3 tools/sdt_fleet.py --transport token --workspace YOUR_WORKSPACE --list
python3 tools/sdt_fleet.py --transport token --workspace YOUR_WORKSPACE \
  --repo first-service --repo mobile-app --sonar
# tokenless pilot from a static list (one slug per line, '#' comments allowed):
python3 tools/sdt_fleet.py --transport ssh --workspace YOUR_WORKSPACE \
  --repo-list /home/wishnu/sdt-fleet/repos-pilot.txt --sonar \
  --work-dir /home/wishnu/sdt-fleet/work --output /home/wishnu/sdt-fleet/runs
```

The second command is a pilot. Omit `--repo` to scan all accessible repositories.
Use `--bitbucket-token-file` instead of the environment variable for a
scheduled job. Use `--jobs 2` to bound concurrent scans, `--limit 10` for a first inventory
slice, and `--output` for artifact storage. Schedule the exact command weekly
with the supplied systemd service and timer after the pilot. Set
`SDT_FLEET_WORKSPACE=...` in `/home/wishnu/.config/sdt-fleet/config`, put the
token in `/home/wishnu/.config/sdt-fleet/bitbucket-token` with mode 0600, and
restrict the configuration directory to mode 0700. The timer is intentionally
not installed or enabled until the token and pilot are ready.

Sonar analysis runs after SDT in the same checkout, importing
`sonar-external.json` into a stable `sdt_<workspace>_<repo>_<hash>` project
key. The central run writes:

- `fleet-manifest.json`: every repository's commit, scan state, artifact path,
  and Sonar/PDF status, including failed checkouts and incomplete scans.
- `fleet-findings.xlsx`: finding register, scanner coverage, and reviewed SAST
  precision sheets. Precision is labelled unmeasured until TP/FP triage exists.
- `fleet-summary.pdf`: portfolio summary for distribution.
- `repositories/<repo>/security-report.pdf`: detailed developer report, plus
  canonical SDT JSON/SARIF/manifest and the Sonar import file.
- `repositories/<repo>/codex-review.md`: a small, redacted packet of uncertain
  SAST results to inspect manually in Codex. It is advisory; verify in source
  before accepting a finding or marking one false positive.

The reviewer ledger is a CSV outside the repository with columns
`repository,fingerprint,verdict,reviewer,reason,reviewed_at`. Verdicts are
`true_positive`, `false_positive`, `needs_context`, or `accepted_risk`.
Pass it as `--triage /private/triage.csv` on later fleet runs or regenerate a
saved workbook with `python3 tools/sdt_fleet_report.py --from
reports/fleet/<run>/fleet-manifest.json --triage /private/triage.csv`.
The workbook is an export; the CSV is the durable review record.

The existing SDT policy can return exit 1 for valid findings. The fleet job
records that as `policy_failed` and continues because the first rollout is
advisory. Exit 2–5, missing artifacts, and missing required scanners remain
visible as coverage failures. `fleet-manifest.json` and the canonical SDT
reports are the source of truth; Sonar is a viewing surface. Triage decisions
are recorded in the CSV with repository, fingerprint, reviewer, and reason so
that rule precision and repeat findings can be measured over time.

Sonar import is confirmed, not assumed. After sonar-scanner exits 0, the
runner polls the Compute Engine task (`/api/ce/task?id=...`) until it reports
`SUCCESS` (`sonar=imported`), `FAILED`/`CANCELED` (`sonar=import_failed`),
or the `--sonar-poll-timeout` deadline (`sonar=import_unconfirmed`). A fleet
run is healthy (exit 0) only when every scan finished, every PDF rendered,
and — when `--sonar` is set — every import was confirmed. Reasons are kept in
`sonarError` fields of `fleet-manifest.json`. Java and Kotlin checkouts are
scanned with a minimal dummy classes directory (`--sonar-classes`) because
their Sonar sensors refuse source-only projects.

Branch views: this SonarQube 10.7 Community install runs the third-party
community branch plugin 1.22.0 (installed under `extensions/plugins/`, loaded
via `-javaagent` in `conf/sonar.properties`; a backup of the pre-plugin
config is `conf/sonar.properties.bak-20260928`). Default-branch fleet scans
never pass `sonar.branch.name` — the analyzed default branch becomes the
project main automatically; Sonar displays that view with the generic name
`main` even when the Git default branch is named differently. Passing
`--sonar-branch` only affects explicit `slug:branch` repo-list entries: their
analyses are submitted as named branch views under the same project. First
analyses of a new project must not carry `sonar.branch.name`: the plugin
then treats the branch as a non-main view whose missing reference branch
fails the Compute Engine import with "Reference branch does not exist".
The plugin is community-maintained and must be kept version-matched when
Sonar is upgraded.

## Database

The local instance runs on PostgreSQL (`sonardb`, credentials in
`/home/wishnu/sd-lab/.sonar-db-password`, mode 0600), configured in
`conf/sonar.properties`; the pre-migration embedded H2 data is archived at
`sonar/h2-data-backup-20260928`. This removes the "embedded database" banner
natively, gives an upgrade path, and is required for 25–200 repository
scans. Sonar data was re-created by re-running the pilot after the switch.

## Detection improvement loop

Inventory languages and current rule hits across 5–10 pilot repositories.
Maintain annotated vulnerable and safe fixtures for authorization, injection,
deserialization, file access, cryptography, data exposure, transport, and
web/mobile risks. Review all hits in the pilot, sample clean paths for misses,
and record precision and seeded-case recall by rule. Use `sdt rules verify`
before shipping a rule; shadow-run new rules and promote them under
`docs/rule-precision.md` only after real-repository triage.

## Reviews, precision and reports

* Reviewers decide findings in SonarQube; `tools/sdt_sonar_sync.py` copies those decisions into the fleet store
  (Safe/False positive -> false_positive, Accepted -> accepted_risk with a 90-day deadline, Fixed/Confirmed ->
  true_positive), idempotently and with an audit event per decision.
* `tools/sdt_rule_precision.py --database $SCP_DATABASE_URL` reports precision per rule from those verdicts and
  recommends keeping, demoting to a Security Hotspot, or disabling noisy rules.
* Each scan's SAST report (.docx) is documented in [SAST report](sast-report.md).
