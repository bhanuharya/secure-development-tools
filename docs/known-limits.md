# Known limits

The reproducible rough edges, in full. The README carries the short list; this
page carries the detail. Nothing here is softened for presentation.

## Status

**Pre-release: `sdt 0.1.0-dev`, schema `secure-dev/v1alpha1`.** The runtime runs
in a Jenkins pipeline scanning a Bitbucket workspace of mobile and web services,
and is exercised end to end in CI on this repository and on the bundled
vulnerable fixture. The `secure-dev/v1alpha1` schemas are not yet a frozen
compatibility contract.

## Subdirectory project roots

Previously, pointing `project.root` at a subdirectory required passing absolute
`SDT_RULES_PACK_DIR` and `--cache` flags because child scanners ran with their
working directory set to `project.root`. The runtime now resolves both the rule
pack directory and scanner native report paths to absolute paths before
spawning child processes, so subdirectory roots work with default relative
flags as well.

## Scanning behaviour worth knowing

- **OpenGrep runs with `--no-git-ignore`**, so a finding can land in a gitignored
  build artifact rather than in source.
- **A full self-scan exits `1` by design.** Scanning this repository with
  `--profile full` reports findings and blockers because the tree ships
  deliberately vulnerable fixtures, redaction-test canaries and vendored rule test
  fixtures. The Dependabot alerts on `fixtures/vulnapp/requirements.txt` are the
  same fixture working as intended: that pinned 2018-era dependency set exists to
  be detected, not repaired.
- **ADR 0003 predates the current fingerprint algorithm.** It documents `sdt-v1`
  while the code emits `sdt-v2` occurrence-level identity.
- **Engines are prerequisites.** `sdt` does not bundle scanners in the local build
  path. Install them yourself or build the container image.
- **Minified and generated files are not analysed by the code scan.** OpenGrep's
  cross-function analysis does not finish on a minified bundle, so a source file
  that is machine-written by its content (20 KB or more, with one line of 5,000
  characters or 250 characters per line on average) is left out. The run manifest
  lists these files per task (`skippedFiles`); Gitleaks and Trivy still read them.
  `SDT_SCAN_GENERATED_FILES=1` scans them after all.
- **OpenGrep runs on at most two cores.** Each worker past the first costs more
  CPU than it saves time: 4 workers took 11% less time than 2 for 37% more CPU,
  and more than 4 took as long or longer. `SDT_SCAN_THREADS` sets another number.
- **OpenGrep is given the rules as one merged file.** Its command line loads rule
  files one by one, 18 s for a typical scan against 2.5 s for one file with the
  same rules. The plan lists every rule file (`args`) next to the command line
  that runs (`execArgs`). A rule file that cannot be merged safely (YAML anchors,
  several documents, a duplicate id) makes the scan load the files one by one, as
  does `SDT_OPENGREP_MERGE_RULES=0`.

## Legacy tree

`src/` is the superseded Python control plane: reference only, not hardened, and
it receives no fixes. Most first-party SAST findings in a self-scan sit there. Its
pytest suite passes locally but is not wired into CI. See
[legacy-control-plane.md](legacy-control-plane.md).

## Not verified

- **Windows**: CI runs `ubuntu-latest` only. The local path is tested on Linux,
  and the runtime uses POSIX assumptions in scanner invocation.
- **Container**: `packaging/Dockerfile` builds and passes a non-root smoke test
  in CI, but no release image is published to a public registry.
- **`fix`, `reachability`, `publish`, `explain`, and the `sbom`/`vex` formats**:
  implemented with unit tests. There is no record of them being used outside
  tests, and no compatibility promise for their output shape.
- **Finding vs. report artifact digests across checkout paths**: individual
  finding fingerprints (`sdt-v2`) are normalized against the project root and
  verified deterministic across distinct checkout paths. Whole-file `sha256`
  digests of `run-manifest.json` / `findings.json` still differ across runs
  because they embed timestamps and run IDs.
