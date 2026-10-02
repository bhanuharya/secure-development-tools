#!/usr/bin/env python3
"""Make SonarQube review decisions hold on every branch of a project.

SonarQube keeps a review decision (a hotspot marked Safe, an issue marked False
positive or Accepted) on the branch where it was made. A new release branch therefore
shows the same finding as undecided again. After a branch or pull request is analysed,
this copies the decisions already made on the project's other branches onto its
undecided findings.

A decision is copied only when the finding is the same one: same rule, same file and
the same line of code (compared as text, so a line that merely moved still matches,
and a line that was edited does not). Each copy carries a comment naming the branch
and date it came from. Nothing is ever reopened, and a finding with no decision on any
branch is left alone.

  SONAR_TOKEN=... python3 tools/sdt_sonar_carry.py --sonar-url http://localhost:9000 \\
      --project-key KEY --branch release/1.1 [--dry-run]
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

# Decisions worth repeating: the reviewer looked at the code and judged it. "Fixed" is
# not one: a finding that is still reported was not fixed on this branch.
HOTSPOT_RESOLUTIONS = {"SAFE": "Safe", "ACKNOWLEDGED": "Acknowledged"}
ISSUE_TRANSITIONS = {"FALSE-POSITIVE": "falsepositive", "FALSE_POSITIVE": "falsepositive",
                     "WONTFIX": "accept", "ACCEPTED": "accept"}
ISSUE_WORDS = {"falsepositive": "False positive", "accept": "Accepted"}


def _path(component: str) -> str:
    return component.split(":", 1)[1] if ":" in component else ""


def signatures(findings: list[dict], line_text) -> dict[tuple, dict]:
    """(rule, path, code line, n-th such line in the file) -> finding.

    ``line_text(path, line)`` returns the source line the finding sits on. Identical
    lines in one file are told apart by their order, so each keeps its own decision.
    """
    seen: Counter = Counter()
    out = {}
    for f in sorted(findings, key=lambda f: (_path(f.get("component", "")), f.get("line") or 0, f.get("key", ""))):
        path = _path(f.get("component", ""))
        rule = f.get("ruleKey") or f.get("rule") or ""
        text = " ".join(line_text(path, f.get("line")).split()) if f.get("line") else ""
        if not path or not rule or (f.get("line") and not text):
            continue  # cannot be recognised on another branch
        base = (rule, path, text or str(f.get("message") or ""))
        out[base + (seen[base],)] = f
        seen[base] += 1
    return out


def plan(undecided: dict[tuple, dict], decided: dict[str, dict[tuple, dict]]) -> list[dict]:
    """What to copy: for each undecided finding, the newest matching decision on another branch."""
    copies = []
    for signature, finding in undecided.items():
        matches = [(source[signature], branch) for branch, source in decided.items() if signature in source]
        if not matches:
            continue
        source, branch = max(matches, key=lambda m: str(m[0].get("updateDate") or ""))
        copies.append({"key": finding["key"], "decision": source["decision"], "from_branch": branch,
                       "decided_on": str(source.get("updateDate") or "")[:10],
                       "path": signature[1], "line": finding.get("line"), "rule": signature[0]})
    return copies


def comment(copy: dict) -> str:
    return (f"Decision carried over by SDT from branch '{copy['from_branch']}' (decided {copy['decided_on']}): "
            f"same rule, file and line of code.")


class Sonar:
    def __init__(self, url: str, token: str, project: str):
        self.url, self.project = url.rstrip("/"), project
        self.auth = "Basic " + base64.b64encode(f"{token}:".encode()).decode()
        self.sources: dict[tuple, list[str]] = {}

    def _open(self, path: str, params: dict, data: bool = False):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "")})
        request = urllib.request.Request(f"{self.url}{path}" + ("" if data else f"?{query}"),
                                         data=query.encode() if data else None)
        request.add_header("Authorization", self.auth)
        return urllib.request.urlopen(request, timeout=60)

    def get(self, path: str, **params) -> dict:
        with self._open(path, params) as response:
            return json.load(response)

    def post(self, path: str, **params) -> None:
        self._open(path, params, data=True).close()

    def paged(self, path: str, key: str, **params) -> list[dict]:
        items, page = [], 1
        while True:
            data = self.get(path, p=page, ps=500, **params)
            items += data.get(key, [])
            total = (data.get("paging") or {}).get("total", data.get("total", 0))
            if page * 500 >= total or not data.get(key):
                return items
            page += 1

    def line_text(self, scope: dict):
        """A (path, line) -> source text reader for one branch or pull request."""
        def read(path: str, line: int | None) -> str:
            cache_key = (path, tuple(sorted(scope.items())))
            if cache_key not in self.sources:
                try:
                    with self._open("/api/sources/raw", {"key": f"{self.project}:{path}", **scope}) as response:
                        self.sources[cache_key] = response.read().decode("utf-8", "replace").splitlines()
                except (OSError, urllib.error.HTTPError):
                    self.sources[cache_key] = []
            lines = self.sources[cache_key]
            return lines[line - 1] if line and 0 < line <= len(lines) else ""
        return read

    def findings(self, scope: dict, decided: bool) -> list[dict]:
        """Hotspots and issues of one scope: the decided ones (with their decision) or the open ones."""
        hotspots = self.paged("/api/hotspots/search", "hotspots", projectKey=self.project,
                              status="REVIEWED" if decided else "TO_REVIEW", **scope)
        issues = self.paged("/api/issues/search", "issues", componentKeys=self.project,
                            resolved="true" if decided else "false", **scope)
        if decided:
            issues += self.paged("/api/issues/search", "issues", componentKeys=self.project,
                                 issueStatuses="ACCEPTED,FALSE_POSITIVE", **scope)
        out, seen = [], set()
        for h in hotspots:
            resolution = str(h.get("resolution") or "")
            if not decided or resolution in HOTSPOT_RESOLUTIONS:
                out.append({**h, "decision": ("hotspot", resolution)})
        for i in issues:
            state = str(i.get("resolution") or i.get("issueStatus") or "").upper()
            if i["key"] in seen or (decided and state not in ISSUE_TRANSITIONS):
                continue
            seen.add(i["key"])
            out.append({**i, "decision": ("issue", ISSUE_TRANSITIONS.get(state, ""))})
        return out

    def apply(self, copy: dict) -> None:
        kind, value = copy["decision"]
        if kind == "hotspot":
            self.post("/api/hotspots/change_status", hotspot=copy["key"], status="REVIEWED", resolution=value,
                      comment=comment(copy))
        else:
            self.post("/api/issues/do_transition", issue=copy["key"], transition=value)
            self.post("/api/issues/add_comment", issue=copy["key"], text=comment(copy))


def main() -> int:
    ap = argparse.ArgumentParser(description="Copy SonarQube review decisions from a project's other branches.")
    ap.add_argument("--sonar-url", required=True)
    ap.add_argument("--project-key", required=True)
    ap.add_argument("--branch", default="", help="the branch just analysed (default: the main branch)")
    ap.add_argument("--pull-request", default="", help="the pull request just analysed, instead of a branch")
    ap.add_argument("--dry-run", action="store_true", help="list what would be copied, change nothing")
    args = ap.parse_args()
    token = os.environ.get("SONAR_TOKEN", "")
    if not token:
        print("sdt_sonar_carry: SONAR_TOKEN is not set", file=sys.stderr)
        return 2
    sonar = Sonar(args.sonar_url, token, args.project_key)
    try:
        branches = sonar.get("/api/project_branches/list", project=args.project_key).get("branches", [])
        main_name = next((b["name"] for b in branches if b.get("isMain")), "")
        target_name = args.branch or main_name
        target = {"pullRequest": args.pull_request} if args.pull_request else {"branch": target_name}
        undecided = signatures(sonar.findings(target, decided=False), sonar.line_text(target))
        decided = {}
        for b in branches:
            if not undecided or (not args.pull_request and b["name"] == target_name):
                continue
            scope = {"branch": b["name"]}
            decided[b["name"]] = signatures(sonar.findings(scope, decided=True), sonar.line_text(scope))
        copies = plan(undecided, decided)
        if not args.dry_run:
            for copy in copies:
                sonar.apply(copy)
    except (OSError, urllib.error.HTTPError, KeyError, ValueError) as exc:
        print(f"sdt_sonar_carry: SonarQube request failed: {exc}", file=sys.stderr)
        return 2
    by_branch: dict[str, int] = defaultdict(int)
    for copy in copies:
        by_branch[copy["from_branch"]] += 1
        kind, value = copy["decision"]
        word = HOTSPOT_RESOLUTIONS.get(value) or ISSUE_WORDS.get(value, value)
        print(f"  {copy['path']}:{copy['line'] or '-'} {copy['rule']} -> {word} (from {copy['from_branch']})")
    origin = ", ".join(f"{n} from {b}" for b, n in sorted(by_branch.items())) or "none to copy"
    print(f"sdt_sonar_carry: {len(undecided)} undecided findings; {len(copies)} decisions "
          f"{'would be ' if args.dry_run else ''}carried over ({origin})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
