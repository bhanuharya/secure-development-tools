# Security posture

What `sdt` does, control by control, and what each control does not cover. This
page holds the detail that used to sit in the README's main reading path.

Verified on the current `main` on Linux. See also [ADR 0002](adr/0002-process-execution.md)
and [SECURITY.md](../SECURITY.md).

## Process execution

- **No shell, ever.** Repository-controlled paths, revisions and image references
  enter `os/exec` as argv only. Config has no command-string fields by
  construction, and unknown keys fail closed.
- Engine stderr and evidence pass through the redactor before persistence or
  display. Captured stdout/stderr is byte-capped.
- Secret-category evidence is replaced with a placeholder in `explain` output.

## Containment

- `project.root` must resolve inside the authorized checkout. A root that escapes
  it is rejected as invalid input (exit `2`):

  ```console
  $ sdt scan --config /tmp/elsewhere.yaml
  sdt: project root "/tmp/sdt-demo/app" escapes the authorized checkout "/path/to/checkout"
  ```

## Fail closed

- A missing or unhealthy required scanner fails the run (`3`), and `3` is never
  a pass.
- A malformed native report is a scanner failure even when the process exited
  zero.
- Unresolvable git bases and fingerprint-version mismatches fail the run instead
  of degrading to a silent pass.
- `sdt explain` is opt-in (`ai.enabled=true`), local, template-based, and cannot
  alter a finding, a verdict or an exit code.

## What these controls do not cover

- **Redaction is pattern-based.** It applies to evidence written by `sdt` and to
  scanner stderr. It is not a guarantee that a secret cannot appear anywhere else
  in your CI logs, your shell history or the engines' own output.
- **Containment is path-based, not a sandbox.** `sdt` does not put scanner
  processes in containers or namespaces. The image in `packaging/Dockerfile` runs
  as non-root, which is packaging, not isolation. Any process isolation comes from
  whatever you run the engines in.
- **The engines are not hardened here.** A vulnerability in OpenGrep, Gitleaks,
  Trivy or a rule in the bundle is outside this project's control, and the rule
  bundle is governed by [docs/rule-precision.md](rule-precision.md).
- **Evidence is not an audit log.** `run-manifest.json` records what ran, with
  what version and what digest. It does not attest that the checkout was
  trustworthy or that a human reviewed the result.
