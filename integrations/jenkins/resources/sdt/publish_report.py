#!/usr/bin/env python3
"""Commit the scan's report to a reports repository on Bitbucket Cloud, where developers can read it.

Each scan overwrites the report of its branch or pull request, so the repository's history is the
history of the findings:

    <repo>/branches/<branch>/report.md        + SAST Report.docx
    <repo>/pull-requests/<id>/report.md       + SAST Report.docx

report.md renders in Bitbucket and diffs line by line. Its address is written to OUT/report-url.txt,
which the pull-request comment links.

Required: OUT, REPO_SLUG, WORKSPACE_NAME, BITBUCKET_TOKEN, SDT_REPORTS_REPO (a repository slug in the
          same workspace, or workspace/slug), and BRANCH or PR_ID
Optional: BITBUCKET_USER (set: the token is an API token of that account; empty: an access token),
          BITBUCKET_GIT (https://bitbucket.org), SCOPE_URL, SRC

The token reaches git through GIT_ASKPASS: never on a command line, in a URL or in the output.
Standard library only.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CATEGORIES = {"sast": "Code", "secret": "Secret", "secrets": "Secret", "sca": "Dependency", "dependency": "Dependency"}
IDENTITY = ["-c", "user.name=SDT security scan", "-c", "user.email=sdt-security-scan@localhost"]
ATTEMPTS = 5


def log(message):
    print(f"[sdt] {message}", flush=True)


def severity(finding):
    return str((finding.get("severity") or {}).get("canonical", "")).lower()


def kind(finding):
    category = str(finding.get("category", "")).lower()
    return CATEGORIES.get(category, category.capitalize() or "Other")


def location(finding):
    where = finding.get("location") or {}
    line = where.get("startLine")
    return f"{where.get('path', '')}:{line}" if line else str(where.get("path", ""))


def cell(text):
    return str(text).replace("|", "\\|").replace("`", "'").replace("\n", " ").strip()


def verdict(out):
    try:
        status = open(os.path.join(out, "quality-gate.txt")).readline().strip()
    except OSError:
        return "NOT COMPLETED"
    return {"OK": "PASSED", "ERROR": "FAILED"}.get(status, "NOT COMPLETED")


def findings(out, pull_request):
    """What the scan reports: for a pull request only what it adds; never what an exception covers."""
    name = "findings-new.json" if pull_request else "findings-report.json"
    for candidate in (name, "findings.json"):
        try:
            items = json.load(open(os.path.join(out, "sdt", candidate)))["findings"]
        except (OSError, ValueError, KeyError):
            continue
        items = [f for f in items if not f.get("suppression")]
        rank = {level: index for index, level in enumerate(SEVERITIES)}
        return sorted(items, key=lambda f: (rank.get(severity(f), len(rank)), location(f)))
    return None


def markdown(repo, scope, scope_url, commit, result, items):
    lines = [f"# Security scan: {repo}", "",
             f"**{result}** · {f'[{scope}]({scope_url})' if scope_url else scope}" + (f" · commit `{commit}`" if commit else ""), ""]
    if items is None:
        lines.append("The scan did not produce a list of findings.")
    elif not items:
        lines.append("No security findings." if "pull request" not in scope else "This pull request adds no new security findings.")
    else:
        counts = {}
        for item in items:
            counts[kind(item)] = counts.get(kind(item), 0) + 1
        lines += [", ".join(f"{count} {name.lower()}" for name, count in sorted(counts.items())) + ".", "",
                  "| Severity | Type | Rule | Location | What |", "| --- | --- | --- | --- | --- |"]
        for item in items:
            rule = str((item.get("rule") or {}).get("id", "")).split(".")[-1]
            # A secret's message can describe the value; its type and place are enough.
            what = "" if kind(item) == "Secret" else cell(item.get("message", ""))[:160]
            lines.append(f"| {cell(severity(item).capitalize())} | {cell(kind(item))} | {cell(rule)} | `{cell(location(item))}` | {what} |")
    if "pull request" in scope:
        lines += ["", "Findings that already exist on the target branch are not listed."]
    lines += ["", "Review decisions (safe, false positive, accepted) are made in SonarQube. "
              "The full report is `SAST Report.docx` in this folder."]
    return "\n".join(lines) + "\n"


class Git:
    def __init__(self, directory, askpass):
        self.directory = directory
        self.env = dict(os.environ, GIT_ASKPASS=askpass, GIT_TERMINAL_PROMPT="0")
        self.env.pop("GIT_CURL_VERBOSE", None)
        self.env.pop("GIT_TRACE", None)

    def run(self, *args, check=True):
        done = subprocess.run(["git", "-c", "credential.helper=", *args], cwd=self.directory, env=self.env,
                              capture_output=True, text=True, timeout=300)
        if check and done.returncode != 0:
            reason = [line for line in done.stderr.splitlines() if line.strip()][-3:]
            raise RuntimeError(f"git {args[0]} failed: " + " / ".join(reason))
        return done


def main():
    env = os.environ
    try:
        out, repo, workspace, token, target = (env[name] for name in
                                               ("OUT", "REPO_SLUG", "WORKSPACE_NAME", "BITBUCKET_TOKEN", "SDT_REPORTS_REPO"))
    except KeyError as missing:
        log(f"report not published: {missing.args[0]} is not set")
        return 1
    pr_id, branch = env.get("PR_ID", ""), env.get("BRANCH", "")
    if pr_id:
        folder, scope = f"{repo}/pull-requests/{pr_id}", f"pull request #{pr_id}"
    elif branch:
        folder, scope = f"{repo}/branches/{re.sub(r'[^A-Za-z0-9._-]+', '_', branch)}", f"branch {branch}"
    else:
        log("report not published: neither PR_ID nor BRANCH is set")
        return 1
    reports_workspace, _, reports_repo = target.rpartition("/")
    reports_workspace = reports_workspace or workspace
    base = (env.get("BITBUCKET_GIT") or "https://bitbucket.org").rstrip("/")
    remote = f"{base}/{reports_workspace}/{reports_repo}.git"

    commit = ""
    if env.get("SRC"):
        done = subprocess.run(["git", "-C", env["SRC"], "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
        commit = done.stdout.strip() if done.returncode == 0 else ""
    result = verdict(out)
    text = markdown(repo, scope, env.get("SCOPE_URL", ""), commit, result, findings(out, bool(pr_id)))
    docx = os.path.join(out, f"SAST Report - {repo}.docx")

    work = tempfile.mkdtemp(prefix="sdt-reports-")
    try:
        askpass = os.path.join(work, "askpass.sh")
        user = "x-bitbucket-api-token-auth" if env.get("BITBUCKET_USER") else "x-token-auth"
        with open(askpass, "w") as handle:
            handle.write(f'#!/bin/sh\ncase "$1" in Username*) echo {user} ;; *) printf "%s" "$BITBUCKET_TOKEN" ;; esac\n')
        os.chmod(askpass, stat.S_IRWXU)
        clone = os.path.join(work, "reports")
        git = Git(work, askpass)
        git.run("clone", "--quiet", "--depth", "1", remote, clone)
        git = Git(clone, askpass)
        head = git.run("symbolic-ref", "--short", "HEAD", check=False).stdout.strip() or "main"
        if git.run("rev-parse", "--verify", "--quiet", "HEAD", check=False).returncode != 0:
            head = "main"  # an empty repository: the first report creates its main branch
        for attempt in range(1, ATTEMPTS + 1):
            destination = os.path.join(clone, folder)
            os.makedirs(destination, exist_ok=True)
            with open(os.path.join(destination, "report.md"), "w") as handle:
                handle.write(text)
            if os.path.isfile(docx):
                shutil.copyfile(docx, os.path.join(destination, "SAST Report.docx"))
            git.run("add", "--all", folder)
            if git.run("diff", "--cached", "--quiet", check=False).returncode == 0:
                log("report unchanged since the last scan")
                break
            git.run(*IDENTITY, "commit", "--quiet", "-m", f"{repo}: {scope} {result.lower()}" + (f" at {commit}" if commit else ""))
            if git.run("push", "--quiet", "origin", f"HEAD:{head}", check=False).returncode == 0:
                break
            if attempt == ATTEMPTS:
                raise RuntimeError("another scan kept pushing first; gave up after several tries")
            # Another scan published in between: start again from what is there now.
            git.run("fetch", "--quiet", "--depth", "1", "origin", head)
            git.run("reset", "--quiet", "--hard", "FETCH_HEAD")
    except (RuntimeError, OSError, subprocess.SubprocessError) as err:
        log(f"report not published: {err}")
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)

    url = f"https://bitbucket.org/{reports_workspace}/{reports_repo}/src/{urllib.parse.quote(head)}/{urllib.parse.quote(folder)}/report.md"
    with open(os.path.join(out, "report-url.txt"), "w") as handle:
        handle.write(url + "\n")
    log(f"report published: {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
