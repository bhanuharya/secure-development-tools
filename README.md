# `sdt` — Secure Development Tools

**One deterministic gate that turns OpenGrep, Gitleaks and Trivy into a single
reproducible verdict on a pull request — on your laptop or in any CI runner.**

`sdt` is a local-first, provider-agnostic scanning runtime. It resolves a
provider-neutral context, plans immutable scanner tasks, executes the engines
through argv-only adapters, normalizes every result into one canonical finding
schema, evaluates a typed YAML policy against a fingerprint baseline, and
**always** writes the same four artifacts — including when the policy fails.

No server, no dashboard, no telemetry, no network by default. Exit codes are the
gate; the artifacts are the evidence.

## What a run looks like

Real output from [`examples/sample-run`](examples/sample-run) — `sdt` scanning
the deliberately vulnerable fixture app shipped in this repo:

```console
$ SDT_RULES_PACK_DIR=$PWD/rules/opengrep-rules \
    sdt scan --profile full --config examples/sample-run/demo.secure-dev.yaml \
      --cache /tmp/sdt-cache --output /tmp/sdt-reports
sdt: status=policy_failed findings=12 (critical=3 high=3 medium=6 low=0 info=0 unknown=0) blockers=4 warnings=0
  scanner opengrep     completed
  scanner trivy-fs     completed
  BLOCK opengrep:00003 sha256:8f5ffe7cea5c (block-new-high-sast)
  BLOCK trivy-fs:00005 sha256:25b8456a83eb (block-new-critical-dependencies)
  BLOCK trivy-fs:00006 sha256:df1187e8bde8 (block-new-critical-dependencies)
  BLOCK trivy-fs:00007 sha256:a72389a32207 (block-new-critical-dependencies)
$ echo $?
1
```

(The pack-dir variable and the absolute cache/output are needed only because
this demo points `project.root` at a subdirectory — see *Known limits*. Against
your own repository root, plain `sdt scan --profile full` is enough.)

The findings behind those blockers (from the committed report):

| Severity | Finding | Where |
|---|---|---|
| high | `python.scp.python.exec.eval` — `eval` on a dynamic string | `app.py:15` |
| medium | `python.scp.python.crypto.weak-md5` — MD5 used for hashing | `app.py:6` |
| critical | CVE-2019-20477 / CVE-2020-14343 / CVE-2020-1747 — PyYAML pinned at 5.1 | `requirements.txt` |

## Artifacts and exit codes

Every run finalizes the same set, before the exit code is returned, so retain
`reports/` even on failure:

| Artifact | Contents |
|---|---|
| `findings.json` | Canonical report, schema `secure-dev/report/v1alpha1` |
| `findings.sarif` | SARIF 2.1.0 for code-scanning UIs and review tooling |
| `run-manifest.json` | Evidence: digests, tool versions, per-task state and native exit codes, artifact checksums |
| `summary.txt` | The one-line verdict plus scanner health and blockers |

Exit codes — the whole point of putting this in a pipeline:

| Code | Status | Meaning |
|---|---|---|
| `0` | passed | Required scanners healthy, policy satisfied |
| `1` | `policy_failed` | Required scanners completed; findings violated policy |
| `2` | `invalid_input` | Bad config, bad revision, containment violation |
| `3` | `execution_failed` | A required scanner or process is not trustworthy — do not read this as a pass |
| `4` | `inconclusive` | Not enough signal to decide |
| `5` | `internal_error` | The runtime itself failed |

## Why teams use it

### For developers

- **The same command locally and in CI.** Every flag reads from an environment
  variable, so a bot sets `SDT_*` and a human copies the logged values to
  reproduce the run bit-for-bit — same plan digest, same findings.
- **Catch it before the push.** `sdt init --hook` installs a pre-commit hook and
  `sdt scan --staged` runs OpenGrep + Gitleaks over staged files only, in
  seconds; Trivy defers to CI with a *visible* skip rather than a silent gap.
  `SKIP_SDT=1` bypasses once, and CI stays the authoritative gate.
- **Fixes the boring ones for you.** `sdt fix` applies whitelisted, versioned
  mechanical transforms (`gha-pin-action/v1`, `py-hashlib-sha256/v1`,
  `py-yaml-safe-load/v1`) as exact-line rewrites, per-file atomic and
  syntax-checked. It never commits, and it never touches secrets.
- **Actionable output, not a dashboard to log into.** Stdout for humans, JSON
  and SARIF for machines, and a policy trace that names the rule which blocked
  each finding.

### For security engineers

- **A rule bundle you can defend.** 153 rules across 138 files, every one
  validated, pinned by upstream commit, and enforced by content hashes —
  `sdt rules verify` checks counts, per-file hashes, bundle hashes and
  per-rule annotated tests. Precision is measured per rule
  ([`docs/rule-precision.md`](docs/rule-precision.md)), not asserted.
- **Legacy debt without the noise.** A fingerprint baseline
  (`sdt baseline create`) marks existing findings, so a PR is judged on what it
  *introduces*. Expiring exceptions require an owner and a reason
  (`.secure-dev/exceptions.yaml`), so suppressions cannot rot unseen.
- **Reachability, not just versions.** Dependency findings carry
  `reachable` / `unreachable` / `unknown` for Go, Python and JS imports, with a
  soundness contract: anything doubtful resolves to `unknown`, and `unknown`
  matches neither policy value.
- **Audit-grade supply chain.** Opt-in CycloneDX SBOM
  (`sbom.cdx.json`) and policy-derived VEX (`vex.cdx.json`), with
  `not_affected` deliberately unwired so VEX cannot over-claim.
- **Secrets never reach the artifacts.** Evidence is redacted before
  persistence, scanner stderr passes through the same redactor, and reports
  carry `redaction.applied: true` rather than a matched value.

### What it deliberately does not do

- **AI cannot change a verdict.** `sdt explain` is opt-in
  (`ai.enabled=true`), local, template-based, and states its own
  non-authority in the output header.
- **No implied pass.** A missing or unhealthy required scanner fails the run
  (`3`); a malformed native report is a scanner failure even if the process
  exited zero.
- **No shell.** Repository-controlled values never reach a shell — every
  subprocess is argv-only (`os/exec`), and unknown config keys fail closed.
- **No outbound scanning.** `project.root` must stay inside the authorized
  checkout; a root that escapes it is rejected with `invalid_input`:

  ```console
  $ sdt scan --config /tmp/elsewhere.yaml
  sdt: project root "/tmp/sdt-demo/app" escapes the authorized checkout "/path/to/checkout"
  ```

## Quickstart

Requires Go 1.24.6 (per `go.mod`) and the three scanner binaries.

```bash
git clone git@github.com:bhanuharya/secure-development-tools.git
cd secure-development-tools
go build -o sdt ./cmd/sdt          # ~1 s, no code generation

./sdt doctor                       # one line per precondition, with the reason a check failed
./sdt init --dry-run               # preview the config before writing it
./sdt plan --profile pr --base origin/main
./sdt scan --profile pr --base origin/main --output reports --cache .cache/sdt
```

`sdt doctor` reports each precondition independently, so a failure names its own
remedy:

```console
git              ok      worktree
history          ok      complete
config           ok      ok
tool:opengrep    ok      /home/…/.local/bin/opengrep
tool:gitleaks    ok      /home/…/.local/bin/gitleaks
tool:trivy-fs    ok      /home/…/.local/bin/trivy
rules            ok      138 rule files
```

Scanner prerequisites, verified at this revision — `sdt` honors
`SDT_OPENGREP_BIN`, `SDT_GITLEAKS_BIN` and `SDT_TRIVY_BIN`:

| Engine | Version verified here | Install |
|---|---|---|
| OpenGrep | 1.29.0 | `https://github.com/opengrep/opengrep/releases/download/v1.29.0/opengrep_manylinux_x86` |
| Gitleaks | 8.30.1 | upstream release binary |
| Trivy | 0.73.0 | upstream install docs |

## Command reference

```bash
./sdt detect                     # languages, manifests, IaC, applicable scanners
./sdt config validate            # typed config; unknown keys fail closed
./sdt doctor                     # environment + blocker explanations
./sdt init --dry-run | --hook    # starter config, or the pre-commit fast path
./sdt plan                       # immutable plan; the digest inputs of a run
./sdt scan                       # execute → normalize → evaluate → report

./sdt baseline create  --from reports/findings.json   # explicit legacy-debt snapshot
./sdt baseline compare --from reports/findings.json   # new / existing / resolved
./sdt policy test      --from reports/findings.json   # re-evaluate a saved report
./sdt rules verify                                    # validate + per-rule tests + manifest hashes
./sdt rules propose    --from reports/                # rank repeat findings, draft rule skeletons
./sdt publish --provider github|bitbucket|gitlab      # offline payloads; never rescans
./sdt explain --finding <id>                          # advisory, needs ai.enabled=true
./sdt fix [--apply] [--only <transform-id>]           # dry-run diff, or write the tree
./sdt version                                         # CLI, schema, adapters, bundled tools
```

## Profiles and scan modes

Profiles live in `.secure-dev.yaml` (this repository's own file is the working
example): `pr` (changed mode, 15 m), `full` (repository mode, 45 m) and
`release` (adds the image scan, requires `--image`, `updateMode: locked`).

| Mode | Scan surface | Used by |
|---|---|---|
| `changed` | Revisions bounded by `--base`/`--head` | `pr` |
| `repository` | The whole checkout | `full`, `release` |
| `staged` | Staged files only (OpenGrep + Gitleaks); Trivy deferred visibly | `--staged`, pre-commit hook |

Gitleaks history handling follows the profile: `pr`/`changed` scan the explicit
`base..head` range, `full`/`release` scan `--all`, and a missing or
unresolvable base **fails closed** rather than silently widening to a
current-tree scan. Shallow clones follow the profile's `missingHistory`
(`fail`/`warn`).

## Policy, baselines and exceptions

Typed YAML policy, no Rego, no expression language, no network (ADR 0004):
ordered rules, first match wins per finding, explicit `defaultAction`, and a
`policy.trace` entry mapping every blocker to the rule that produced it.

```yaml
policy:
  rules:
    - id: block-reachable-critical-deps
      match:
        categories: [dependency-vulnerability]
        severities: [critical]
        baselineStates: [new, unknown]
        reachable: [reachable]   # `unknown` matches neither value: uncertainty
      action: fail               # can neither trigger nor silence a rule
```

Baselines are keyed by `sdt-v2` fingerprints — `sha256` over category,
adapter/rule, normalized repo-relative path and semantic context, so identity
survives line movement. The context is the engine-provided finding content, with
the start line used only as a last-resort disambiguator, so two distinct issues
of the same rule in one file never share identity. The algorithm version is
recorded in every finding and baseline, and a mismatch **fails closed** with an
explicit migration error instead of silently re-baselining. A fingerprint-version mismatch **fails
closed** with an explicit migration error rather than silently re-baselining.
Exceptions require an owner, a reason and an expiry.

## The governed rule bundle

```console
$ sdt rules verify
rules: 138 files, 153 rules, 0 invalid
validate: clean
tests: 134 rule files passed, 4 without tests, 0 failed
```

- Hand-written rules (`scp.*`) cover common, Go, HCL, Java, JavaScript,
  Dart/Flutter, Kotlin, Python, TypeScript and YAML; on top of those, curated
  `lang/security` subsets of `semgrep-rules` and Aikido's OpenGrep rules are
  vendored under `rules/opengrep-rules/vendor/` with their licenses and
  upstream revisions preserved ([`rules/NOTICE`](rules/NOTICE), [ADR 0007](docs/adr/0007-sast-rule-governance.md)).
- Terraform provider rules are deliberately excluded — Trivy owns IaC.
- Cross-function taint is enabled (`--taint-intrafile`); the four rule files
  without annotated tests stay visible in the verify output rather than silent.
- Rule bytes feed the plan digest, so identical inputs — rules included —
  produce identical plans.

## CI integration

[`examples/`](examples/README.md) carries the provider-neutral envelope: a
provider maps its native variables to `SDT_*`, invokes the engine exactly once,
and retains `reports/`. Scanning behavior never moves into provider YAML.

| Variable | Meaning |
|---|---|
| `SDT_PROFILE` | Profile name from `.secure-dev.yaml` |
| `SDT_EVENT` | `local`, `pull_request`, `push`, `schedule`, `release` |
| `SDT_BASE` / `SDT_HEAD` | Revisions bounding a changed-mode scan |
| `SDT_IMAGE` | Image reference for `release` profiles |
| `SDT_OUTPUT_DIR` / `SDT_CACHE_DIR` | Artifact root / cache root |
| `SDT_CONFIG` | Config path override |
| `SDT_OFFLINE` | Disable network updates |

This repository's own CI uses the same engine: `scripts/ci_gate_smoke.sh` runs
the demo scan and asserts the gate still blocks the vulnerable fixture with all
four artifacts finalized (exit `1`, not `3`).

Flags beat environment on every key. Worked examples:
[`examples/github`](examples/github/workflow-env.sh),
[`examples/gitlab`](examples/gitlab/ci-env.sh),
[`examples/bitbucket`](examples/bitbucket/pipeline-env.sh),
[`examples/generic-ci`](examples/generic-ci/pipeline.sh),
[`examples/jenkins`](examples/jenkins/README.md),
[`examples/local`](examples/local/scan.sh).

## Output formats

`outputs.formats` selects the set; `console`, `json`, `sarif` and `manifest`
are the defaults.

| Format | Artifact |
|---|---|
| `console` | stdout |
| `json` | `findings.json` |
| `sarif` | `findings.sarif` |
| `manifest` | `run-manifest.json` |
| `junit` | `policy.junit.xml` |
| `sbom` | `sbom.cdx.json` (merged Trivy CycloneDX inventory) |
| `vex` | `vex.cdx.json` (policy-derived; `not_affected` never emitted) |

`summary.txt` is always written.

### Offline tooling

`tools/` holds stdlib-only, network-free helpers that consume the same artifacts
— no server, no database, no AI:

| Tool | Purpose |
|---|---|
| `tools/sdt_to_sonar.py` | `findings.json` → SonarQube generic-issue JSON via `sonar.externalIssuesReportPaths` (SonarQube 10.3+, no plugin) |
| `tools/dart_to_sonar.py` | `dart analyze` / `flutter analyze` output → the same generic-issue format, because OpenGrep cannot parse Dart |
| `tools/sdt_to_pdf.py` | Offline PDF report from `findings.json` plus `run-manifest.json` |
| `tools/sdt_knowledge.py` | Shared, versioned finding knowledge (risk / assess / fix / references) behind the PDF renderer |

## Container

[`packaging/Dockerfile`](packaging/Dockerfile) builds a non-root image with the
`sdt` binary, the pinned scanner binaries, the default rule bundle and a tool
manifest (versions, checksums, licenses, provenance). OCI image is the
portability baseline; `latest` is never referenced in examples — immutable
version or digest only. Update modes: `locked` (release default), `database`,
`rules`, `offline`. No telemetry: metrics come from local run manifests.

## Configuration

`.secure-dev.yaml` is typed (`schemas/config-v1alpha1.json`) and validated
before anything runs. Top-level sections: `apiVersion`, `kind`, `metadata`,
`project`, `profiles`, `scanners`, `outputs`, `policy`, `baseline`,
`exceptions`, `publish`, `ai`, `runtime`, `extends`. Unknown keys fail closed.
`publish.enabled` and `ai.enabled` default to `false`, and enabling either never
alters exit codes or artifacts.

## Repository layout

```text
cmd/sdt/          CLI entry point
internal/         the runtime: app (commands), config, context, plan, execute,
                  scanner (opengrep/gitleaks/trivy adapters), finding, policy,
                  baseline, rules, reachability, fix, report, publish
pkg/schema/       exported schema helpers
tools/            offline, stdlib-only report/integration helpers (Sonar, PDF,
                  Dart analyzer converter, shared finding knowledge)
rules/            governed rule bundle + manifest.yaml + NOTICE
schemas/          config and finding JSON Schemas
examples/         provider envelopes + a committed sample run
docs/             ADRs, rule precision policy, legacy reference doc
src/              legacy Python control plane (reference only, no fixes)
fixtures/         test fixtures, including a deliberately vulnerable demo app
tests/            pytest suite for the legacy control plane
```

## Design decisions

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-implementation-language-go.md) | Go for the runtime |
| [0002](docs/adr/0002-process-execution.md) | Direct argv execution, no shell; byte-capped capture; redacted stderr |
| [0003](docs/adr/0003-fingerprinting.md) | Fingerprint algorithm and fail-closed migration (the code emits `sdt-v2` occurrence-level identity; the ADR text still describes `sdt-v1`) |
| [0004](docs/adr/0004-policy-dsl.md) | Purpose-built typed YAML policy, no Rego |
| [0005](docs/adr/0005-packaging.md) | OCI-first distribution, no hosted service, no telemetry |
| [0006](docs/adr/0006-publish-explain.md) | Offline publish payloads; local-only advisory explanations |
| [0007](docs/adr/0007-sast-rule-governance.md) | Curate, pin, prove — rule governance policy |
| [0008](docs/adr/0008-bets-staged-supplychain-fixes.md) | Staged fast path, reachability, safe fixes, SBOM/VEX, rule mining |

## Security posture

- **No shell, ever.** Repository-controlled paths, revisions and image
  references enter `os/exec` as argv only; config has no command-string fields
  by construction and unknown keys fail closed (ADR 0002).
- **Containment.** `project.root` must resolve inside the authorized checkout;
  escaping roots are rejected as invalid input.
- **Redaction at the boundary.** Evidence and scanner stderr pass through the
  redactor before persistence or display; secret-category evidence is replaced
  with a placeholder in `explain`.
- **Fail closed.** Missing required scanners, unresolvable git bases, malformed
  native reports and fingerprint-version mismatches all fail the run instead of
  degrading to a silent pass.
- **Advisory AI, never authoritative.** Off by default, local template only,
  cannot alter a finding, a verdict or an exit code.

Report a vulnerability as described in [`SECURITY.md`](SECURITY.md).

## Status and known limits

**Pre-release: `sdt 0.1.0-dev`, schema `secure-dev/v1alpha1`.** The runtime is
exercised end-to-end on this repository and on the bundled vulnerable fixture,
but it has not been adopted by a live pipeline yet, and `pkg/schema` is not a
frozen compatibility contract.

- **CI runs the Go gate, the rule harness, an engine smoke test and a tools
  check** (`.github/workflows/ci.yml`). Actions are pinned by commit SHA and
  scanner downloads are verified against recorded SHA-256 digests. The status
  badge is added once the first run on `main` is green — until then, treat the
  commands in this README as verified locally at this revision.
- **Subdirectory project roots need two overrides.** With `project.root` pointed
  at a subdirectory, relative paths stop agreeing between the runtime and the
  child processes:
  - the rule pack is resolved under that root, so OpenGrep exits `7` with an
    **empty** diagnostic — set `SDT_RULES_PACK_DIR` to the absolute pack path;
  - the default relative cache (`--cache .cache/sdt`) makes `trivy-fs` write its
    `--output` path relative to the scanned artifact root, which fails with
    `unable to write results: failed to create a file` and turns the run into
    exit `3` `execution_failed` — pass an absolute `--cache` (and, for symmetry,
    `--output`).

  Both are reproduced in this repository by
  `examples/sample-run/demo.secure-dev.yaml`, which is why its documented command
  carries both flags. A normal repository-root project needs neither.
- **OpenGrep runs with `--no-git-ignore`**, so a finding can land in a gitignored
  build artifact (e.g. a test cache) rather than in source.
- **A full self-scan exits `1` by design.** Scanning this repository with
  `--profile full` reports 127 findings (49 blockers), because the tree ships
  deliberately vulnerable fixtures, redaction-test canaries and vendored rule test
  fixtures. The Dependabot alerts on `fixtures/vulnapp/requirements.txt` are the
  same fixture working as intended: that pinned 2018-era dependency set exists to
  be detected, not to be repaired.
- **`src/` is the superseded Python control plane** — kept as reference, not
  hardened and not fixed, and it is where most first-party SAST findings sit (see
  the legacy doc below). Its pytest suite passes locally but is not wired into
  CI.
- **ADR 0003 predates the current fingerprint algorithm**: it documents `sdt-v1`
  while the code emits `sdt-v2` occurrence-level identity.
- **Engines are prerequisites.** `sdt` does not bundle scanners in the local build
  path; install them yourself or use the container image.

## License

MIT — see [`LICENSE`](LICENSE). That covers the code and rules authored for this
project (`scp.*`).

Third-party material keeps its own terms, listed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and
[`rules/NOTICE`](rules/NOTICE). In particular the vendored `semgrep-rules`
subsets under `rules/opengrep-rules/vendor/semgrep/` remain under the **Semgrep
Rules License v1.0** (internal business use; not for competing products or SaaS
offerings) — an MIT file at the repository root does not relicense them, and the
built-in rule bundle should not be redistributed as part of a competing
scanning product.

## Legacy: the Python control plane

The superseded FastAPI + SQLModel platform (multi-engine orchestration,
Bitbucket intake, dashboard, DAST gating) lives in the tree as reference only
and is documented separately: [`docs/legacy-control-plane.md`](docs/legacy-control-plane.md).
