# Sample run (real output)

A complete `sdt` run, committed so a visitor can see real artifacts without
running anything: the raw output of one command against the deliberately
vulnerable fixture app in [`fixtures/vulnapp`](../../fixtures/vulnapp).

## Provenance

| Field | Value |
|---|---|
| Command | `SDT_RULES_PACK_DIR=$PWD/rules/opengrep-rules sdt scan --profile full --config examples/sample-run/demo.secure-dev.yaml --cache /tmp/sdt-cache --output /tmp/sdt-reports` |
| Target | `fixtures/vulnapp` (SQL injection, MD5, `eval`, and a pinned 2018-era dependency set) |
| Profile | `full`, scanners `opengrep` + `trivy-fs`, both required |
| `sdt` | 0.1.0-dev, schema `secure-dev/v1alpha1`, `sdt-v2` fingerprints |
| Engines | opengrep 1.29.0, trivy 0.73.0 |
| Result | `policy_failed`, exit `1`, 12 findings (3 critical / 3 high / 6 medium), 4 blockers |

To reproduce on your own checkout:

```bash
go build -o sdt ./cmd/sdt
SDT_RULES_PACK_DIR=$PWD/rules/opengrep-rules \
  ./sdt scan --profile full --config examples/sample-run/demo.secure-dev.yaml \
    --cache /tmp/sdt-cache --output /tmp/sdt-reports
```

The committed [`demo.secure-dev.yaml`](demo.secure-dev.yaml) is the exact config
used (it points `project.root` at `fixtures/vulnapp`). Both the pack-dir variable
and the absolute cache are required for a subdirectory-rooted project — see
*Known limits* in the root README; with the default relative cache, `trivy-fs`
fails and the run exits `3`. Scanner versions must match the table above for
identical output.

## Files

| File | What it is |
|---|---|
| `summary.txt` | The human-readable verdict: status, counts, scanner health, blockers |
| `findings.json` | Canonical report (`secure-dev/report/v1alpha1`) — the machine contract |
| `findings.sarif` | SARIF 2.1.0 for code-scanning UIs |
| `run-manifest.json` | Evidence: digests, tool versions, per-task state and native exit codes, artifact checksums |

## Sanitization

**None was required.** The artifacts were checked for local-environment
disclosure before committing — the count of the local user path across
`findings.json`, `findings.sarif`, `run-manifest.json` and `summary.txt` is
**zero** — and the files are committed byte-for-byte as produced. Findings carry
redacted evidence only (`redaction.applied: true`); the fixture's
credential-shaped strings are synthetic. (An earlier revision of this sample
needed a one-string edit because vendored rule IDs embedded the absolute
checkout path; rule-ID normalization now strips that prefix, and the check above
is what confirms it stays fixed.)
