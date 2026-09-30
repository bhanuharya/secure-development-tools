#!/usr/bin/env python3
"""One-repository fleet manifest, so a single scan still exports Excel and PDF.

tools/sdt_fleet_report.py reads a fleet run directory: a fleet manifest beside a
`repositories/<slug>/` tree that holds that scan's findings.json and
run-manifest.json. A Jenkins job that scans one repository gets the same reports
without a fleet run by pointing this tool at that scan's artifacts and writing
--out to the run root. The slug must equal the artifact directory name, because
that is how the report joins the record to its findings.

Usage:
  python3 tools/sdt_repo_manifest.py \
      --findings run/repositories/app/findings.json \
      --run-manifest run/repositories/app/run-manifest.json \
      --slug app --branch main --workspace example --commit abc123 \
      --out run/fleet-manifest.json

Exit 0 on success, 2 on an invalid slug, a missing input file, an unreadable
report, or an unwritable destination.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# sdt_fleet only defines functions at import time, so the slug grammar and the
# timestamp format stay in one place across the fleet and single-repo paths.
from sdt_fleet import NAME, utc_now


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]


def build_manifest(findings: dict, *, slug: str, branch: str, commit: str, workspace: str,
                   sonar: str, pdf: str, sdt_exit: int | None = None) -> dict:
    """One fleet record in the shape sdt_fleet.scan_repository produces."""
    run_id = str(findings.get("runId") or "")
    suffix = hashlib.sha256(f"{workspace}/{slug}".encode()).hexdigest()[:10]
    project_key = f"sdt_{workspace}_{slug}".replace(".", "_").replace("-", "_")[:160] + f"_{suffix}"
    record = {"repository": slug, "branch": branch, "commit": commit,
              "status": str(findings.get("status") or "execution_failed"),
              "sonar": sonar, "pdf": pdf,
              "findings": len(findings.get("findings") or []),
              "runId": run_id, "completedAt": utc_now(),
              "sonarProjectKey": project_key}
    if sdt_exit is not None:
        record["sdtExitCode"] = sdt_exit
    return {"schemaVersion": "sdt/fleet/v1", "runId": run_id or new_run_id(), "workspace": workspace,
            "generatedAt": utc_now(), "selectedRepositories": 1, "repositoryCount": 1,
            "repositories": [record]}


def write_manifest(manifest: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".tmp")
    pending.write_text(json.dumps(manifest, indent=2) + "\n")
    os.replace(pending, path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Synthesize a single-repository sdt/fleet/v1 manifest")
    parser.add_argument("--findings", required=True, type=Path, help="canonical findings.json from `sdt scan`")
    parser.add_argument("--run-manifest", required=True, type=Path,
                        help="that scan's run-manifest.json; the report reads adapter states from it")
    parser.add_argument("--slug", required=True, help="repository slug, named like its artifact directory")
    parser.add_argument("--branch", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--commit", default="")
    parser.add_argument("--sonar-status", default="imported", help="recorded Sonar state for the Coverage sheet")
    parser.add_argument("--pdf-status", default="ready", help="recorded per-repository PDF state")
    parser.add_argument("--out", required=True, type=Path, help="fleet manifest to write, at the run root")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not NAME.fullmatch(args.slug):
        print(f"sdt_repo_manifest: --slug is not a repository slug: {args.slug}", file=sys.stderr)
        return 2
    absent = [path for path in (args.findings, args.run_manifest) if not path.is_file()]
    if absent:
        print(f"sdt_repo_manifest: input not found: {', '.join(str(path) for path in absent)}", file=sys.stderr)
        return 2
    try:
        findings = json.loads(args.findings.read_text())
    except (OSError, ValueError) as exc:
        print(f"sdt_repo_manifest: invalid findings.json: {exc}", file=sys.stderr)
        return 2
    try:
        run_manifest = json.loads(args.run_manifest.read_text())
    except (OSError, ValueError) as exc:
        print(f"sdt_repo_manifest: invalid run-manifest.json: {exc}", file=sys.stderr)
        return 2
    sdt_exit = run_manifest.get("exitCode")
    manifest = build_manifest(findings, slug=args.slug, branch=args.branch, commit=args.commit,
                              workspace=args.workspace, sonar=args.sonar_status, pdf=args.pdf_status,
                              sdt_exit=sdt_exit if isinstance(sdt_exit, int) else None)
    try:
        write_manifest(manifest, args.out)
    except OSError as exc:
        print(f"sdt_repo_manifest: could not write {args.out}: {exc}", file=sys.stderr)
        return 2
    record = manifest["repositories"][0]
    print(f"fleet manifest: {args.out} (repo={record['repository']} status={record['status']} "
          f"findings={record['findings']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
