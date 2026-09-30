#!/usr/bin/env python3
"""Turn one immutable fleet run into durable baseline and review state.

src/api/fleet_store.py does the work; this CLI only chooses the database and
prints what changed. --database is exported as SCP_DATABASE_URL *before* src.api
is imported, so the engine built here is the one named on the command line and
the dashboard's own database is never opened unless --database names it.

Usage:
  python3 tools/sdt_fleet_ingest.py --run-dir reports/fleet/<runId>
  python3 tools/sdt_fleet_ingest.py --run-dir reports/fleet/<runId> \
      --approve-baseline --project app --branch main --approved-by alice \
      --reason "pilot baseline, all open findings accepted as existing"

Exit 0 on success, 2 on a bad flag combination, a missing artifact, or input
the service refuses (an unknown project, a verdict without an owner).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FALLBACK_DATABASE = "sqlite:///./sdt-fleet.db"
SUMMARY_ORDER = ("repositories", "scans", "already_ingested", "missing_report", "created",
                 "observed", "duplicate", "unfingerprinted", "resolved")
# Suppression is report-side now: the review store records the decision, the
# canonical results keep the finding, and the readers filter it by verdict.
REMOVED_FLAGS = {"--generate-suppressions": "was removed: accepted risks are filtered at report "
                                            "time by verdict, never written to a .trivyignore",
                 "--dir": "was removed with --generate-suppressions"}


def default_database() -> str:
    """No personal home path: the deployed environment, else the working directory."""
    return os.environ.get("SCP_DATABASE_URL", "").strip() or FALLBACK_DATABASE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ingest SDT fleet runs into the control-plane database")
    parser.add_argument("--run-dir", type=Path,
                        help="fleet run directory holding fleet-manifest.json (required for ingestion)")
    parser.add_argument("--database", default=default_database(),
                        help="SQLAlchemy URL (default: $SCP_DATABASE_URL, else ./sdt-fleet.db)")
    parser.add_argument("--approve-baseline", action="store_true",
                        help="freeze one project+branch's open findings as the active baseline")
    parser.add_argument("--project", help="repository slug to approve a baseline for")
    parser.add_argument("--branch", help="branch the baseline applies to")
    parser.add_argument("--approved-by", help="who approved the baseline")
    parser.add_argument("--reason", default="", help="why the baseline was approved")
    return parser


def refuse_removed_flags(argv: list[str]) -> None:
    """Explain a retired mode in its own words, before argparse rejects it generically."""
    for argument in argv:
        flag = argument.split("=", 1)[0]
        if flag in REMOVED_FLAGS:
            raise ValueError(f"{flag} {REMOVED_FLAGS[flag]}")


def _mode(args: argparse.Namespace) -> str:
    if args.approve_baseline:
        missing = [flag for flag, value in (("--project", args.project), ("--branch", args.branch),
                                            ("--approved-by", args.approved_by), ("--reason", args.reason))
                   if not value]
        if missing:
            raise ValueError("--approve-baseline requires " + ", ".join(missing))
        return "baseline"
    if not args.run_dir.is_dir():
        raise ValueError(f"--run-dir is not a directory: {args.run_dir}")
    return "ingest"


def _project(session, slug: str):
    """A repository slug must name exactly one project, or the baseline is meaningless."""
    from sqlmodel import select

    from src.api.database import Project

    matches = session.exec(select(Project).where(Project.repo_slug == slug).order_by(Project.id)).all()
    if not matches:
        raise ValueError(f"no project recorded for repository {slug!r}; ingest a run first")
    if len(matches) > 1:
        raise ValueError(f"repository {slug!r} exists in {len(matches)} workspaces; "
                         "the dashboard owns workspace-scoped registration")
    return matches[0]


def _run(args: argparse.Namespace, mode: str) -> None:
    from src.api import fleet_store
    from src.api.database import Session, engine, init_db

    init_db()
    with Session(engine) as session:
        if mode == "baseline":
            baseline = fleet_store.approve_baseline(session, _project(session, args.project).id,
                                                     args.branch, args.approved_by, args.reason)
            print(f"baseline: id={baseline.id} project={baseline.project_id} branch={baseline.branch} "
                  f"findings={baseline.finding_count} approved_by={baseline.approved_by}")
            return
        summary = fleet_store.ingest_run(args.run_dir, session)
        line = " ".join(f"{key}={summary.get(key, 0)}" for key in SUMMARY_ORDER)
        print(f"fleet ingest: {line}")
        if not summary.get("scans") and summary.get("already_ingested"):
            print("nothing changed: every repository in this run is already ingested")


def main() -> int:
    try:
        refuse_removed_flags(sys.argv[1:])
        args = build_parser().parse_args()
        mode = _mode(args)
    except ValueError as exc:
        print(f"sdt_fleet_ingest: {exc}", file=sys.stderr)
        return 2
    # Set before src.api is imported: that module builds its engine from this URL.
    os.environ["SCP_DATABASE_URL"] = args.database
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        _run(args, mode)
    except (OSError, ValueError) as exc:
        print(f"sdt_fleet_ingest: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
