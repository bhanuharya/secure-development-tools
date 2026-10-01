#!/usr/bin/env python3
"""Copy review decisions made in SonarQube into the SDT fleet store.

Reviewers work in SonarQube (mark a Security Hotspot Safe, an issue False positive or
Accepted); SDT keeps the one review history. This reads the decided hotspots and issues
of one project branch and records each as a verdict through src/api/fleet_store.py:

  hotspot Safe              -> false_positive
  hotspot Fixed/Acknowledged-> true_positive
  issue False positive      -> false_positive
  issue Accepted (won't fix)-> accepted_risk, expiring after --accept-days
  issue Confirmed/Fixed     -> true_positive

Run it after each analysis (the Jenkins library does) or on a schedule. It is idempotent.

  SONAR_TOKEN=... python3 tools/sdt_sonar_sync.py --sonar-url http://localhost:9000 \\
      --project-key KEY --branch main --repository app --database sqlite:///fleet.db
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOTSPOT_VERDICTS = {"SAFE": "false_positive", "FIXED": "true_positive", "ACKNOWLEDGED": "true_positive"}
ISSUE_VERDICTS = {"FALSE-POSITIVE": "false_positive", "FALSE_POSITIVE": "false_positive",
                  "WONTFIX": "accepted_risk", "ACCEPTED": "accepted_risk",
                  "CONFIRMED": "true_positive", "FIXED": "true_positive"}
ISSUE_WORDS = {"WONTFIX": "accepted", "FALSE-POSITIVE": "false positive"}
HISTORY_LOCATION = re.compile(r"in git history: (?P<path>[^\s:]+):(?P<line>\d+)")


def _component_path(component: str) -> str:
    return component.split(":", 1)[1] if ":" in component else ""


def decisions_from_sonar(hotspots: list[dict], issues: list[dict]) -> list[dict]:
    """Sonar hotspots and issues -> fleet_store decisions; undecided ones are left out."""
    decisions = []
    for h in hotspots:
        verdict = HOTSPOT_VERDICTS.get(str(h.get("resolution") or ""))
        if h.get("status") == "REVIEWED" and verdict:
            decisions.append({"key": h["key"], "rule": h.get("ruleKey", ""), "path": _component_path(h.get("component", "")),
                              "line": h.get("line"), "verdict": verdict, "reviewer": h.get("assignee") or "",
                              "reason": f"SonarQube hotspot reviewed as {h['resolution'].title()}"})
    for i in issues:
        state = str(i.get("resolution") or i.get("issueStatus") or i.get("status") or "").upper()
        verdict = ISSUE_VERDICTS.get(state)
        if not verdict:
            continue
        path, line = _component_path(i.get("component", "")), i.get("line")
        history = HISTORY_LOCATION.search(i.get("message", ""))
        if not path and history:
            # A project-level history secret: its message names where it was found.
            path, line = history.group("path"), int(history.group("line"))
        decisions.append({"key": i["key"], "rule": i.get("rule", ""), "path": path, "line": line, "verdict": verdict,
                          "reviewer": i.get("assignee") or "",
                          "reason": f"SonarQube issue marked {ISSUE_WORDS.get(state, state.replace('_', ' ').lower())}"})
    return decisions


def _sonar_get(url: str, token: str, path: str, **params) -> dict:
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "")})
    request = urllib.request.Request(f"{url.rstrip('/')}{path}?{query}")
    request.add_header("Authorization", "Basic " + base64.b64encode(f"{token}:".encode()).decode())
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def _paged(url: str, token: str, path: str, key: str, **params) -> list[dict]:
    items, page = [], 1
    while True:
        data = _sonar_get(url, token, path, p=page, ps=500, **params)
        items += data.get(key, [])
        total = (data.get("paging") or {}).get("total", data.get("total", 0))
        if page * 500 >= total or not data.get(key):
            return items
        page += 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Copy SonarQube review decisions into the SDT fleet store.")
    ap.add_argument("--sonar-url", required=True)
    ap.add_argument("--project-key", required=True)
    ap.add_argument("--branch", required=True, help="the branch as recorded in the fleet store")
    ap.add_argument("--sonar-branch", default="", help="Sonar branch parameter (default: none for the main branch)")
    ap.add_argument("--repository", required=True, help="repository slug of the fleet project")
    ap.add_argument("--database", default=os.environ.get("SCP_DATABASE_URL", "") or "sqlite:///./sdt-fleet.db")
    ap.add_argument("--accept-days", type=int, default=90, help="deadline given to risks accepted in SonarQube")
    args = ap.parse_args()
    token = os.environ.get("SONAR_TOKEN", "")
    if not token:
        print("sdt_sonar_sync: SONAR_TOKEN is not set", file=sys.stderr)
        return 2
    try:
        scope = {"branch": args.sonar_branch}
        hotspots = _paged(args.sonar_url, token, "/api/hotspots/search", "hotspots", projectKey=args.project_key,
                          status="REVIEWED", **scope)
        issues = _paged(args.sonar_url, token, "/api/issues/search", "issues", componentKeys=args.project_key,
                        resolved="true", types="VULNERABILITY,BUG,CODE_SMELL", **scope)
        issues += _paged(args.sonar_url, token, "/api/issues/search", "issues", componentKeys=args.project_key,
                         issueStatuses="CONFIRMED", **scope)
    except OSError as exc:
        print(f"sdt_sonar_sync: cannot read SonarQube: {exc}", file=sys.stderr)
        return 2
    decisions = decisions_from_sonar(hotspots, issues)

    os.environ["SCP_DATABASE_URL"] = args.database
    sys.path.insert(0, str(ROOT))
    from sqlmodel import select

    from src.api import fleet_store
    from src.api.database import Project, Session, engine, init_db

    init_db()
    with Session(engine) as session:
        project = session.exec(select(Project).where(Project.repo_slug == args.repository)).first()
        if project is None:
            print(f"sdt_sonar_sync: no fleet project {args.repository!r}; ingest a run first", file=sys.stderr)
            return 2
        result = fleet_store.apply_sonar_decisions(session, project.id, args.branch, decisions, args.accept_days)
    print(f"sdt_sonar_sync: {len(decisions)} decisions in SonarQube: applied={result['applied']} "
          f"unchanged={result['unchanged']} unmatched={result['unmatched']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
