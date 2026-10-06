#!/usr/bin/env python3
"""List the open pull requests on Bitbucket Cloud that have commits no scan has seen yet.

For a Jenkins that Bitbucket cannot reach with a webhook: a job runs this every few minutes and
starts a scan for each line it prints. A pull request is due when its newest commit is not the one
named in the scan's comment ("Scanned commit ..."), so a new pull request and a new push are both
picked up. Each commit is listed once: what was listed is remembered in the state file, so a scan
that cannot comment is not started again and again.

Prints one line per pull request that is due: repository, id, source branch, target branch, commit
(tab-separated).

Required: WORKSPACE_NAME, BITBUCKET_TOKEN, SDT_POLL_REPOS (repository slugs, separated by spaces or commas)
Optional: BITBUCKET_USER, BITBUCKET_API, SDT_POLL_STATE (.sdt-pr-poll.json)

No token is ever printed. Standard library only.
"""
import json
import os
import re
import sys
import urllib.parse

from pr_comment import Bitbucket
from sdt_common import required

SCANNED = re.compile(r"Scanned commit `([0-9a-f]{7,40})`")


def same_commit(one, other):
    return bool(one and other) and (one.startswith(other) or other.startswith(one))


def due(client, workspace, repo, listed):
    """Open pull requests of one repository whose newest commit was neither scanned nor listed before."""
    quoted = f"/repositories/{urllib.parse.quote(workspace, safe='')}/{urllib.parse.quote(repo, safe='')}"
    url, found = f"{client.api}{quoted}/pullrequests?state=OPEN&pagelen=50", []
    while url:
        page = client.call("GET", url)
        for pull in page.get("values", []):
            source, target = pull.get("source") or {}, pull.get("destination") or {}
            commit = str((source.get("commit") or {}).get("hash", ""))
            key = f"{workspace}/{repo}#{pull['id']}"
            if not commit or same_commit(listed.get(key, ""), commit):
                continue
            comment = client.own_comment(f"{quoted}/pullrequests/{pull['id']}/comments") or {}
            scanned = SCANNED.search((comment.get("content") or {}).get("raw", ""))
            if not (scanned and same_commit(scanned.group(1), commit)):
                found.append((repo, str(pull["id"]), (source.get("branch") or {}).get("name", ""),
                              (target.get("branch") or {}).get("name", ""), commit))
            listed[key] = commit
        url = page.get("next")
    return found


def main():
    env = os.environ
    values = required("pull requests not listed", "WORKSPACE_NAME", "BITBUCKET_TOKEN", "SDT_POLL_REPOS")
    if values is None:
        return 1
    workspace, token, repos = values
    state = env.get("SDT_POLL_STATE") or ".sdt-pr-poll.json"
    try:
        listed = json.load(open(state))
    except (OSError, ValueError):
        listed = {}
    client = Bitbucket(env.get("BITBUCKET_API") or "https://api.bitbucket.org/2.0", token, env.get("BITBUCKET_USER", ""))
    status = 0
    for repo in re.split(r"[\s,]+", repos.strip()):
        try:
            for pull in due(client, workspace, repo, listed):
                print("\t".join(pull), flush=True)
        except RuntimeError as err:
            print(f"[sdt] {repo}: pull requests not listed: {err}", file=sys.stderr, flush=True)
            status = 1
    with open(state, "w") as handle:
        json.dump(listed, handle, indent=1)
    return status


if __name__ == "__main__":
    sys.exit(main())
