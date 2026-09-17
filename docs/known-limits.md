# Known limits

The reproducible rough edges, in full. The README carries the short list; this
page carries the detail. Nothing here is softened for presentation.

## Status

**Pre-release: `sdt 0.1.0-dev`, schema `secure-dev/v1alpha1`.** The runtime is
exercised end to end on this repository and on the bundled vulnerable fixture.
It has not been adopted by a live pipeline. The `secure-dev/v1alpha1` schemas are
not a frozen compatibility contract.

## Subdirectory project roots need two overrides

With `project.root` pointed at a subdirectory, relative paths stop agreeing
between the runtime and its child processes:

- the rule pack resolves under that root, so OpenGrep exits `7` with an **empty**
  diagnostic. Set `SDT_RULES_PACK_DIR` to the absolute pack path.
- the default relative cache (`--cache .cache/sdt`) makes `trivy-fs` write its
  `--output` path relative to the scanned artifact root, which fails with
  `unable to write results: failed to create a file` and turns the run into exit
  `3` `execution_failed`. Pass an absolute `--cache`, and for symmetry an absolute
  `--output`.

Both are reproduced by `examples/sample-run/demo.secure-dev.yaml`, which is why
its documented command carries both flags. A repository-root project needs
neither.

## Scanning behaviour worth knowing

- **OpenGrep runs with `--no-git-ignore`**, so a finding can land in a gitignored
  build artifact rather than in source.
- **A full self-scan exits `1` by design.** Scanning this repository with
  `--profile full` reports 127 findings and 49 blockers, because the tree ships
  deliberately vulnerable fixtures, redaction-test canaries and vendored rule test
  fixtures. The Dependabot alerts on `fixtures/vulnapp/requirements.txt` are the
  same fixture working as intended: that pinned 2018-era dependency set exists to
  be detected, not repaired.
- **ADR 0003 predates the current fingerprint algorithm.** It documents `sdt-v1`
  while the code emits `sdt-v2` occurrence-level identity.
- **Engines are prerequisites.** `sdt` does not bundle scanners in the local build
  path. Install them yourself or build the container image.

## Legacy tree

`src/` is the superseded Python control plane: reference only, not hardened, and
it receives no fixes. Most first-party SAST findings in a self-scan sit there. Its
pytest suite passes locally but is not wired into CI. See
[legacy-control-plane.md](legacy-control-plane.md).

## Not verified

- **Windows**: CI runs `ubuntu-latest` only. The local path is tested on Linux,
  and the runtime uses POSIX assumptions in scanner invocation.
- **Container**: `packaging/Dockerfile` exists and builds a non-root image, but no
  image is published and the image path is not exercised in CI.
- **`fix`, `reachability`, `publish`, `explain`, and the `sbom`/`vex` formats**:
  implemented with unit tests. There is no record of them being used outside
  tests, and no compatibility promise for their output shape.
- **Fingerprint stability across checkout paths**: a fresh run of the documented
  sample reproduces the counts, the blockers and the exit code, but the `sha256`
  values in the committed `examples/sample-run` report do not match a fresh run
  from a different working directory. Treat the hashes as run-local until this is
  explained.
