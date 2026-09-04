# CI examples: provider at the edge

Every example here follows the same contract (PRD P-04): the provider only
checks out source, maps its native CI variables to the neutral `SDT_*`
environment, invokes the engine exactly once, and retains `reports/`.
Scanning behavior — profiles, scanners, policy, baselines — lives in
`.secure-dev.yaml` and is never edited per provider.

## Layout

| Directory | Use when | What it does |
|---|---|---|
| `local/` | Laptop runs, debugging CI failures | Explicit `--base/--head` flags, no provider involved |
| `generic-ci/` | Any runner (Jenkins, Buildkite, …) | Pinned container, read-only workspace, retained artifacts |
| `github/` | GitHub Actions, PRs included | Maps `GITHUB_SHA` + base ref to `SDT_*`, then delegates to `generic-ci` |
| `gitlab/` | GitLab CI, MRs included | Maps `CI_COMMIT_SHA` / `CI_MERGE_REQUEST_*` to `SDT_*`, then delegates |
| `bitbucket/` | Bitbucket Pipelines, PRs included | Maps `BITBUCKET_*` to `SDT_*`, then delegates |

## Neutral environment contract

| Variable | Meaning | Example |
|---|---|---|
| `SDT_PROFILE` | Scan profile from `.secure-dev.yaml` | `pr` |
| `SDT_EVENT` | `local`, `pull_request`, `push`, `schedule`, `release` | `pull_request` |
| `SDT_BASE` / `SDT_HEAD` | Revisions bounding a changed-mode scan | `origin/main` / `$GITHUB_SHA` |
| `SDT_IMAGE` | Image reference for `release` profiles | `registry/app@sha256:…` |
| `SDT_OUTPUT_DIR` / `SDT_CACHE_DIR` | Artifact root / cache root | `reports` / `.cache/sdt` |
| `SDT_OFFLINE` | Disable network updates (`true`/`1`) | `true` |
| `SDT_CONFIG` | Config path override | `.secure-dev.yaml` |

Flags beat environment on every key (`sdt scan --profile pr ...`), so a
developer reproduces any CI run locally by copying the logged values.

## Exit codes (the gate)

`0` passed · `1` policy_failed · `2` invalid_input · `3` execution_failed ·
`4` inconclusive · `5` internal_error. Reports are finalized *before* the
exit code is returned, so always retain `reports/` even on failure.
