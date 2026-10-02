# `sdt` — Secure Development Tools

[![ci](https://github.com/bhanuharya/secure-development-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/bhanuharya/secure-development-tools/actions/workflows/ci.yml)

`sdt` runs OpenGrep, Gitleaks and Trivy over a repository or a pull-request diff
and returns one verdict: a policy decision, an exit code, and four evidence
files. It runs on your machine or in a CI runner, with no server, no dashboard
and no telemetry.

## Why sdt

Most teams already have the scanners. What they lack is one answer per pull
request that developers trust and security can defend. `sdt` is built for that:

- **One gate, three engines.** Code (SAST), secrets and vulnerable dependencies
  are normalized into a single finding schema and judged by one policy file.
  You stop reconciling three report formats and three severity scales.
- **Only new problems block.** Every finding gets a stable, content-derived
  fingerprint. Existing debt goes into a baseline, so a legacy codebase can adopt
  the gate today without a cleanup sprint, and nothing new slips in afterwards.
- **Fails closed.** A scanner that is missing, crashes or times out produces exit
  `3`, never a green build. Every run writes a manifest with engine versions,
  rule digests and native exit codes, so a result can be audited later.
- **Low noise by design.** Rules are curated and versioned with per-rule tests and
  hash checks in CI, and a precision report tells you which rules to keep,
  demote or disable based on how reviewers actually decided.
- **Mobile is covered.** Dart and Flutter rules ship alongside Go, Java, Kotlin,
  JavaScript/TypeScript, Python, YAML and Terraform, a gap most open-source
  SAST setups leave open.
- **Fits the tools you have.** SARIF for GitHub/GitLab code scanning, an import
  into SonarQube (with a companion plugin for native Dart issues), CI templates
  for GitHub, GitLab, Bitbucket and Jenkins, and a Word report developers can act
  on: code first, each finding with its excerpt, a fixed advisory and a link to
  the exact line in the scanned commit.
- **Nothing leaves your machine.** No service, no account, no telemetry. Secrets
  are redacted from evidence and reports, and a test plants a key to prove it.
- **Scales past one repo.** Fleet mode scans a whole Bitbucket workspace on a
  schedule, keeps history in a local store, and syncs review decisions back from
  SonarQube.

**Status: pre-release** (`sdt 0.1.0-dev`, schema `secure-dev/v1alpha1`).
Runs on Linux in a Jenkins pipeline ([`integrations/jenkins/`](integrations/jenkins/README.md))
that scans a Bitbucket workspace of mobile and web repositories, and against this repository and its bundled vulnerable
fixture in CI. The schema is not frozen yet.

## What you would use it for

You are reviewing a pull request and you want a gate that either passes or fails,
with a reason you can paste into the review. Point `sdt` at the checkout: it runs
the three engines, normalizes their output into one finding schema, evaluates a
typed policy against your accepted-findings baseline, writes the artifacts, and
exits non-zero if something new crosses the line.

Here is a real run, this repository scanning the deliberately vulnerable fixture
app it ships. The findings are the fixture working as designed, not a claim about
the repository:

```console
$ SDT_RULES_PACK_DIR=$PWD/rules/opengrep-rules \
    sdt scan --profile full --config examples/sample-run/demo.secure-dev.yaml \
      --cache /tmp/sdt-cache --output /tmp/sdt-reports
sdt: status=policy_failed findings=12 (critical=3 high=3 medium=6 low=0 info=0 unknown=0) blockers=4 warnings=0
  scanner opengrep     completed
  scanner trivy-fs     completed
  BLOCK opengrep:00003 sha256:7230d1c41a92 (block-new-high-sast)
  BLOCK trivy-fs:00005 sha256:7f12a60ae478 (block-new-critical-dependencies)
  BLOCK trivy-fs:00006 sha256:fb8c3b7400ab (block-new-critical-dependencies)
  BLOCK trivy-fs:00007 sha256:0e3e057cb85d (block-new-critical-dependencies)
$ echo $?
1
```

Twelve findings, four of them new and blocking, exit `1`. The `sha256` values
identify specific occurrences, which is how the baseline records accepted debt.
The two flags are only needed because this demo points `project.root` at a
subdirectory, see [known limits](docs/known-limits.md).

## Smallest working example

Prerequisites, each of which `sdt doctor` checks and explains:

- git, on Linux or macOS
- OpenGrep 1.29.0, Gitleaks 8.30.1 and Trivy 0.73.0 on `PATH`, or point
  `SDT_OPENGREP_BIN`, `SDT_GITLEAKS_BIN`, `SDT_TRIVY_BIN` at them
- Go 1.24.6 only if you build from source
- Python 3 only for the offline report helpers; Docker only if you build the
  container image yourself

```bash
git clone https://github.com/bhanuharya/secure-development-tools.git
cd secure-development-tools
go build -o sdt ./cmd/sdt

./sdt doctor                     # one line per precondition, with the reason a check failed
./sdt init --dry-run             # preview the starter config; nothing is written
./sdt scan --profile full --output reports
```

Results land in `reports/`: `findings.json` (schema `secure-dev/v1alpha1`),
`findings.sarif`, `run-manifest.json` (engine versions, digests, per-task state
and native exit codes) and `summary.txt`. The cache defaults to `.cache/sdt`.
No image download is needed for the local path; no container image is published
yet.

For a pull request, bound the scan to changed revisions instead of the whole
tree:

```bash
./sdt plan --profile pr --base origin/main
./sdt scan --profile pr --base origin/main
```

A `pr` plan refuses to run without a merge base rather than falling back to a
full scan.

## How it works

Each engine runs as a direct argv process, never through a shell. Its native
report is parsed into one finding schema, and every finding gets a content-derived
fingerprint so the same occurrence keeps its identity between runs. A typed YAML
policy is evaluated against a baseline of accepted fingerprints, and the run
always writes the same four artifacts before returning an exit code: `0` passed,
`1` policy failed, `2` invalid input, `3` execution failed, `4` inconclusive, `5`
internal error. `3` is never a pass, so a missing or unhealthy scanner cannot look
green.

## When to use this, and when not to

Use it if you want one command that gates a pull request across SAST, secrets and
dependencies, with policy as a file, a baseline for existing debt, and evidence
attached to the review, and you would rather not run a service to get that. It is
also the reason the second engine is worth wiring up: normalization across
engines plus one policy is what the tool contributes.

Skip it if your current setup already gives you that. `sdt` is not a better
OpenGrep and it is not a replacement for SonarQube's review UI. If one engine
behind your existing CI gate is enough, another gate will not help.

## Limitations

The full list with reproduction steps is in
[`docs/known-limits.md`](docs/known-limits.md). The material ones:

- **Pre-release.** Schema is not frozen; expect breaking changes before 1.0.
- **Engines are prerequisites.** They are not bundled in the local build path.
- **No scanner isolation.** The image runs as non-root, but `sdt` does not
  sandbox the engines. Process isolation is whatever you run them in.
- **Redaction is pattern-based**, applied to evidence and scanner stderr. It is
  not a guarantee about your own CI logs.
- **`fix`, `reachability`, `publish`, `explain` and the `sbom`/`vex` formats are
  implemented and unit-tested, with no record of use outside tests.**
- **A full self-scan of this repository exits `1` by design**, because the tree
  ships fixtures that exist to be detected.

CI on `main` builds the Go code, verifies the rule bundle against manifest hashes
and per-rule tests, and runs an end-to-end smoke test that asserts the gate still
blocks the vulnerable fixture.

## Developing

```bash
go build ./... && go test ./...
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q
```

Machine-specific paths and tokens are read from flags or environment variables,
never from tracked files; see [`docs/fleet-scanning.md`](docs/fleet-scanning.md)
for the fleet runner's settings.

## Documentation

- [`docs/adr/`](docs/adr/) — decisions, including why the runtime was rebuilt in Go
- [`docs/known-limits.md`](docs/known-limits.md) — reproducible rough edges
- [`docs/security-posture.md`](docs/security-posture.md) — what each control does and does not cover
- [`docs/rule-precision.md`](docs/rule-precision.md) — rule governance
- [`docs/false-positives.md`](docs/false-positives.md) — secret-scanning defaults, dependency reachability, and how to check a finding locally
- [`docs/fleet-scanning.md`](docs/fleet-scanning.md) — scheduled workspace scans, SonarQube import, fleet store, review sync
- [`docs/sast-report.md`](docs/sast-report.md) — the per-scan SAST report (.docx) developers receive
- [`SECURITY.md`](SECURITY.md) — reporting a vulnerability
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and [`rules/NOTICE`](rules/NOTICE) — licenses, including the vendored Semgrep rules
- [`integrations/jenkins/`](integrations/jenkins/README.md) — Jenkins shared library, scanner image and SonarQube setup for per-PR, on-demand and nightly fleet scans
- [`examples/`](examples/README.md) — CI envelopes for GitHub, GitLab, Bitbucket, Jenkins and generic runners
- [`docs/legacy-control-plane.md`](docs/legacy-control-plane.md) — the superseded Python platform, kept as reference
