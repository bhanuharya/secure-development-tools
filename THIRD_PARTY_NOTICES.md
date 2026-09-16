# Third-party notices

This repository is MIT-licensed (see [`LICENSE`](LICENSE)) **except** for the
third-party material listed below, which keeps its own terms. The authoritative,
machine-enforced record for the rule bundle is [`rules/manifest.yaml`](rules/manifest.yaml)
(pinned revisions, expected counts, per-file and bundle hashes), summarised in
[`rules/NOTICE`](rules/NOTICE).

## Vendored rules

### `semgrep-rules` subsets — `rules/opengrep-rules/vendor/semgrep/`

- Upstream: <https://github.com/semgrep/semgrep-rules>
- Revision: `40b8c63f75dc7c22c8a77482d73bfb864b146f7e`
- Source scope: curated `lang/security` subsets for Python, JavaScript, Go,
  Kotlin, Java, C, Rust, YAML (Kubernetes / GitHub Actions) and JSON (AWS).
  `audit/` trees, autofix fixtures and Terraform provider packs are excluded;
  see [`docs/rule-precision.md`](docs/rule-precision.md).
- License: **Semgrep Rules License v1.0** — see
  [`rules/opengrep-rules/vendor/semgrep/LICENSE.semgrep-rules`](rules/opengrep-rules/vendor/semgrep/LICENSE.semgrep-rules)
  and <https://semgrep.dev/legal/rules-license>.
  Permitted for internal business use; **not** for use in competing products or
  SaaS offerings. These files are not relicensed by this repository's MIT
  license, and the bundled rule set must not be redistributed as part of a
  competing scanning product.

### Aikido OpenGrep rules — `rules/opengrep-rules/vendor/aikido/`

- Upstream: <https://github.com/AikidoSec/opengrep-rules>
- Revision: `7ac79affecf709eb7263a243b518a417cd7e0ab2`
- License: MIT — see
  [`rules/opengrep-rules/vendor/aikido/LICENSE`](rules/opengrep-rules/vendor/aikido/LICENSE)
  (Copyright (c) 2025 Aikido Security BV).

## Rules authored for this project

Rules under `rules/opengrep-rules/` outside `vendor/` (identifiers prefixed
`scp.`) are original work and are covered by this repository's MIT license.

## Scanner engines

OpenGrep, Gitleaks and Trivy are **not** vendored in the local build path: `sdt`
executes binaries you install, and they remain under their own upstream
licenses. The container image in [`packaging/Dockerfile`](packaging/Dockerfile)
does bundle pinned scanner binaries; the tool manifest generated for that image
records their versions, checksums, licenses and provenance — consult it (and each
upstream project's `LICENSE`) before redistributing the image.

## Python dependencies (legacy)

`requirements.txt` and the legacy Python control plane under `src/` declare
dependencies but do not vendor them; those packages remain under their own
licenses.
