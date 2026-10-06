#!/usr/bin/env python3
"""Post the result of a pull-request scan as a comment on the Bitbucket Cloud pull request.

Runs after scan.sh and reports.sh. The comment says whether the scan passed, lists what the pull
request adds, and links the SAST report. A later scan of the same pull request updates the comment
instead of adding another one.

Required: OUT, REPO_SLUG, WORKSPACE_NAME, PR_ID, BITBUCKET_TOKEN
Optional: BITBUCKET_USER (set: Basic auth with an API token; empty: the token is an access token),
          BITBUCKET_API (https://api.bitbucket.org/2.0), SDT_PR_REPORT_UPLOAD (1|0: put the .docx in
          the repository's Downloads; never done for a public repository), BUILD_URL, SONAR_HOST_URL, SRC
          OUT/report-url.txt (written by publish_report.py): linked as the report, and nothing is uploaded

The token is never printed. Standard library only.
"""
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

MARKER = "### SDT security scan"
MAX_ROWS = 10
SEVERITIES = ["critical", "high", "medium", "low", "info"]
CATEGORIES = {"sast": "Code", "secret": "Secret", "secrets": "Secret", "sca": "Dependency", "dependency": "Dependency"}


def log(message):
    print(f"[sdt] {message}", flush=True)


class Bitbucket:
    def __init__(self, api, token, user=""):
        self.api = api.rstrip("/")
        if user:
            self.auth = "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
        else:
            self.auth = "Bearer " + token

    def call(self, method, url, body=None, content_type="application/json"):
        if not url.startswith(self.api + "/"):
            raise RuntimeError("refusing to send the token outside the Bitbucket API")
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Authorization", self.auth)
        request.add_header("Accept", "application/json")
        if body is not None:
            request.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
        except urllib.error.HTTPError as err:
            detail = ""
            try:
                detail = json.loads(err.read()).get("error", {}).get("message", "")
            except Exception:
                pass
            raise RuntimeError(f"Bitbucket {method} answered {err.code} {detail}".strip()) from None
        return json.loads(raw) if raw.strip() else {}

    def json(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        return self.call(method, f"{self.api}{path}", body)

    def upload(self, path, name, data):
        boundary = uuid.uuid4().hex
        safe = name.replace('"', "")
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{safe}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
        self.call("POST", f"{self.api}{path}", body, f"multipart/form-data; boundary={boundary}")

    def own_comment(self, path):
        """The newest comment an earlier scan left on this pull request, if any."""
        url, found = f"{self.api}{path}?pagelen=100", None
        for _ in range(20):
            page = self.call("GET", url)
            for comment in page.get("values", []):
                raw = (comment.get("content") or {}).get("raw", "")
                if not comment.get("deleted") and raw.startswith(MARKER):
                    found = comment
            url = page.get("next")
            if not url:
                break
        return found


def verdict(out):
    """PASSED / FAILED from the SonarQube quality gate; NOT COMPLETED when the scan never got there."""
    try:
        lines = open(os.path.join(out, "quality-gate.txt")).read().splitlines()
    except OSError:
        return "NOT COMPLETED", []
    status = lines[0].strip() if lines else ""
    if status == "OK":
        return "PASSED", []
    if status == "ERROR":
        return "FAILED", [line.strip() for line in lines[1:] if line.strip()]
    return "NOT COMPLETED", []


def new_findings(out):
    try:
        findings = json.load(open(os.path.join(out, "sdt", "findings-new.json")))["findings"]
    except (OSError, ValueError, KeyError):
        return None
    rank = {name: index for index, name in enumerate(SEVERITIES)}
    return sorted(findings, key=lambda f: (rank.get(severity(f), len(rank)), location(f)))


def severity(finding):
    return str((finding.get("severity") or {}).get("canonical", "")).lower()


def kind(finding):
    return CATEGORIES.get(str(finding.get("category", "")).lower(), str(finding.get("category", "") or "Other").capitalize())


def location(finding):
    where = finding.get("location") or {}
    line = where.get("startLine")
    return f"{where.get('path', '')}:{line}" if line else str(where.get("path", ""))


def cell(text):
    return str(text).replace("|", "\\|").replace("`", "'").replace("\n", " ")


def body(result, conditions, findings, links, commit):
    lines = [f"{MARKER}: {result}", ""]
    if findings is None:
        lines.append("The scan did not produce a list of findings. See the build log.")
    elif not findings:
        lines.append("This pull request adds no new security findings.")
    else:
        counts = {}
        for finding in findings:
            counts[kind(finding)] = counts.get(kind(finding), 0) + 1
        summary = ", ".join(f"{count} {name.lower()}" for name, count in sorted(counts.items()))
        lines += [f"This pull request adds **{len(findings)}** new security finding{'s' if len(findings) != 1 else ''} ({summary}).", "",
                  "| Severity | Type | Rule | Location |", "| --- | --- | --- | --- |"]
        for finding in findings[:MAX_ROWS]:
            rule = str((finding.get("rule") or {}).get("id", "")).split(".")[-1]
            lines.append(f"| {cell(severity(finding).capitalize())} | {cell(kind(finding))} | {cell(rule)} | `{cell(location(finding))}` |")
        if len(findings) > MAX_ROWS:
            lines += ["", f"{len(findings) - MAX_ROWS} more in the report."]
    if result == "FAILED" and conditions:
        lines += ["", "Quality gate conditions not met: " + "; ".join(cell(c) for c in conditions) + "."]
    if result == "NOT COMPLETED":
        lines += ["", "The scan did not finish, so this is not a pass. See the build log."]
    if links:
        lines += ["", " · ".join(f"[{label}]({url})" for label, url in links)]
    lines += ["", "Findings that already exist on the target branch are not counted."
              + (f" Scanned commit `{commit}`." if commit else "")]
    return "\n".join(lines)


def scanned_commit(src):
    if not src:
        return ""
    try:
        return subprocess.run(["git", "-C", src, "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                              timeout=20, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def main():
    env = os.environ
    try:
        out, repo, workspace, pr_id, token = (env[name] for name in ("OUT", "REPO_SLUG", "WORKSPACE_NAME", "PR_ID", "BITBUCKET_TOKEN"))
    except KeyError as missing:
        log(f"pull request comment: {missing.args[0]} is not set")
        return 1
    client = Bitbucket(env.get("BITBUCKET_API") or "https://api.bitbucket.org/2.0", token, env.get("BITBUCKET_USER", ""))
    quoted = f"/repositories/{urllib.parse.quote(workspace, safe='')}/{urllib.parse.quote(repo, safe='')}"
    result, conditions = verdict(out)
    findings = new_findings(out)

    links = []
    report = os.path.join(out, f"SAST Report - {repo}.docx")
    build_url = env.get("BUILD_URL", "")
    try:
        # publish_report.py committed the report to the reports repository.
        published = open(os.path.join(out, "report-url.txt")).read().strip()
    except OSError:
        published = ""
    if published:
        links.append(("Report", published))
        folder = published[:-len("report.md")] if published.endswith("/report.md") else ""
        if folder and os.path.isfile(os.path.join(out, "security-report.pdf")):
            links.append(("PDF", folder + "security-report.pdf"))
        if folder and os.path.isfile(report):
            links.append(("Word (.docx)", folder + "SAST%20Report.docx"))
    elif os.path.isfile(report):
        name = f"SAST Report - {repo} - PR {pr_id}.docx"
        uploaded = False
        if env.get("SDT_PR_REPORT_UPLOAD", "1") == "1":
            try:
                # Downloads are readable by everyone who can read the repository.
                if client.json("GET", quoted).get("is_private") is True:
                    client.upload(f"{quoted}/downloads", name, open(report, "rb").read())
                    uploaded = True
                else:
                    log("repository is not private: the report is not put in its Downloads")
            except RuntimeError as err:
                log(f"report not uploaded: {err}")
        if uploaded:
            links.append(("Full report (.docx)", f"https://bitbucket.org/{workspace}/{repo}/downloads/{urllib.parse.quote(name)}"))
        elif build_url:
            links.append(("Full report (.docx)", f"{build_url}artifact/out/{urllib.parse.quote(os.path.basename(report))}"))
    try:
        key = open(os.path.join(out, "sonar-project-key")).read().strip()
    except OSError:
        key = ""
    if key and env.get("SONAR_HOST_URL"):
        links.append(("SonarQube", f"{env['SONAR_HOST_URL'].rstrip('/')}/dashboard?id={urllib.parse.quote(key)}&pullRequest={urllib.parse.quote(pr_id)}"))
    if build_url:
        links.append(("Build", build_url))

    text = body(result, conditions, findings, links, scanned_commit(env.get("SRC", "")))
    comments = f"{quoted}/pullrequests/{urllib.parse.quote(pr_id, safe='')}/comments"
    try:
        previous = client.own_comment(comments)
        if previous:
            client.json("PUT", f"{comments}/{previous['id']}", {"content": {"raw": text}})
        else:
            client.json("POST", comments, {"content": {"raw": text}})
    except RuntimeError as err:
        log(f"pull request comment not posted: {err}")
        return 1
    log(f"pull request comment {'updated' if previous else 'posted'}: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
