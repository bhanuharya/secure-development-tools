# Security policy

`Secure Development Tools` (`sdt`) is a security tool for authorized work on
systems you own or are contracted to assess. See
[`docs/legacy-control-plane.md`](docs/legacy-control-plane.md) for the
superseded Python control plane, which is reference material and receives no
security fixes.

## Reporting a vulnerability

**Please do not open a public issue containing exploit details, payloads or
proof-of-concept code.**

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab → **Advisories** → **Report a vulnerability**. That thread is visible only to
you and the maintainer.

If the form is unavailable to you, open a public issue titled exactly
`security: private contact request` containing **no** technical detail — just a
request for a private channel — and the maintainer will respond there with one.

Please include, once you have a private channel:

- the revision (`sdt version`, or the commit you built from),
- the exact command, config and input that reproduces it,
- observed vs expected behaviour, and
- whether the affected run had a workable `run-manifest.json` you can attach.

## Scope

In scope — the runtime under `cmd/`, `internal/` and `tools/`:

- command execution and argument handling (the no-shell contract, ADR 0002);
- report/policy correctness that could turn a **blocking** finding into a
  passing exit code, or silently drop findings, baselines or exceptions;
- secret redaction bypasses that place a credential-shaped value in
  `findings.json`, `findings.sarif`, `summary.txt` or stdout;
- containment failures — a scan, path or image reference reaching outside the
  authorized checkout;
- fingerprint collisions or instability that could let a known finding evade a
  baseline;
- config parsing that accepts unknown keys or otherwise fails open;
- publish/explain payloads that leak unredacted data or misstate authority.

Out of scope:

- **The superseded Python control plane under `src/`.** It is kept for reference
  only and is not maintained.
- **The deliberately vulnerable fixtures** (`fixtures/`, `testdata/`, rule test
  fixtures, redaction-test canaries). Findings there are the point of the
  fixtures, not defects in the tool. Do not report the fixture's
  credential-shaped strings as leaked secrets.
- **Bugs in OpenGrep, Gitleaks or Trivy themselves** — please report those
  upstream.
- **Your own deployment's hardening**: how you bind, proxy or authenticate a
  copy of this tool is your operational responsibility.

Testing the tool is expected to be non-destructive. Only test deployments you
own or are explicitly authorized to test, and do not use this project's name to
justify scanning third-party systems.

## What to expect

This is a pre-release project (`0.1.0-dev`) maintained by one person, without a
bug bounty. Reports are handled on a best-effort basis; no SLA is offered. Only
the current `main` is supported. Please allow a reasonable window for a fix and
a release before publishing details, and coordinate the disclosure timing with
the maintainer so users have a patched revision first.
