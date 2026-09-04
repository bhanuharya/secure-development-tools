# ADR 0001: Implementation language is Go

Date: 2026-09-04
Status: accepted (supersedes PRD D-01 provisional answer)

## Context

PRD v0.1 §21 prefers a compiled language for a single binary, typed
contracts, concurrency, and cross-platform distribution, with Go as the
provisional greenfield choice. Milestone 0 had to decide based on evidence
whether to keep the existing Python control plane or rebuild.

The existing tree (`src/api/`, `src/dashboard/`, `src/scanners/`) is a
FastAPI + SQLite hosted control plane with a Bitbucket/ZAP-coupled
orchestrator. The PRD target is a local-first, provider-neutral CLI + OCI
image with immutable plans, canonical findings, deterministic policy, and
stable exit codes. The gap is architectural, not incremental: server/DB,
dashboard, and provider-coupled intake have no counterpart in the target.

## Decision

Full rebuild in Go as module `github.com/bhanuharya/secure-development-tools`,
command `sdt`. The Python tree is retained untouched as reference; all new
work targets the Go implementation.

## Rationale

- Single static binary via `CGO_ENABLED=0 go build` for multi-arch OCI
  (PRD REL-001); no libgit2/C dependency that a Rust `git2` approach
  would drag in.
- Scanner ecosystem (OpenGrep, Gitleaks, Trivy) is Go; version pinning and
  behavior parity are simpler in the same toolchain.
- Scan orchestration is I/O-bound subprocess management; Go's goroutines
  meet EXEC-001 bounds with far less complexity than async Rust.
- Larger DevSecOps/platform hiring pool for a future company pilot (M8).

## Consequences

- New packages under `cmd/sdt`, `internal/...`; contracts in PRD Part III
  are normative, directory layout illustrative.
- Git operations use argv `git` invocation (SEC-001), not go-git, to keep
  `CGO_ENABLED=0` static builds and exact CLI semantics.
