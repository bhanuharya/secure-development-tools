#!/usr/bin/env python3
"""Post the result of a pull-request scan as a comment on the Bitbucket Cloud pull request.

Runs after scan.sh and reports.sh. The comment says whether the scan passed, lists what the pull
request adds (and what it fixes), and links the reports. A later scan of the same pull request
updates the comment instead of adding another one.

What the pull request adds is read from SonarQube, so the comment and the SonarQube page it links
agree; when SonarQube cannot be asked, it is the scanners' own list (findings-new.json). Everything
is rule output: no model takes part.

Required: OUT, REPO_SLUG, WORKSPACE_NAME, PR_ID, BITBUCKET_TOKEN
Optional: BITBUCKET_USER (set: Basic auth with an API token; empty: the token is an access token),
          BITBUCKET_API (https://api.bitbucket.org/2.0), SDT_PR_REPORT_UPLOAD (1|0: put the .docx in
          the repository's Downloads; never done for a public repository), BUILD_URL, SRC,
          SONAR_HOST_URL + SONAR_TOKEN (the pull request's issues and hotspots), PR_BASE
          OUT/report-url.txt (written by publish_report.py): linked as the report, and nothing is uploaded

No token is ever printed. Standard library only.
"""
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

MARKER = "### SDT security scan"
MAX_ROWS = 15
MAX_FIXED = 5
LEVELS = ["critical", "high", "medium", "low", "info"]
SONAR_SEVERITY = {"BLOCKER": "critical", "CRITICAL": "high", "MAJOR": "medium", "MINOR": "low", "INFO": "info"}
CATEGORIES = {"sast": "Code", "secret": "Secret", "secrets": "Secret", "sca": "Dependency", "dependency": "Dependency",
              "dependency-vulnerability": "Dependency", "misconfiguration": "Configuration", "iac": "Configuration"}
RATINGS = {"1": "A", "2": "B", "3": "C", "4": "D", "5": "E"}
SECRET_RULE = re.compile(r"^secrets:|(^|[:._-])(secret|gitleaks|api-key|access-key|private-key|password|token|credential)", re.I)
DEPENDENCY_RULE = re.compile(r"vulnerable-dependency|(^|:)(CVE-\d|GHSA-|NSWG-|trivy)", re.I)
ADVISORY = re.compile(r"\b(CVE-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3}|NSWG-ECO-\d+)\b", re.I)
# "CVE-2017-5941 in node-serialize 0.0.4 (...)" or "node-serialize@0.0.4": the package and its version.
PACKAGE = re.compile(r"(?:\bin\s+|^\s*)([@A-Za-z0-9._/-]+)[ @](\d[^\s:,()]*)")
# A long unbroken run of key-like characters is never needed to explain a finding.
KEY_LIKE = re.compile(r"(?<![A-Za-z0-9/+_=-])(?=[A-Za-z0-9/+_=-]*\d)(?=[A-Za-z0-9/+_=-]*[A-Za-z])[A-Za-z0-9/+_=-]{24,}")


def log(message):
    print(f"[sdt] {message}", flush=True)


def get_json(url, authorization):
    request = urllib.request.Request(url, headers={"Authorization": authorization, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


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
        safe_name = name.replace('"', "")
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{safe_name}"\r\n'
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


# ------------------------------------------------------------------ verdict
def condition(line):
    """'new_vulnerabilities ERROR 2' as a person would say it."""
    parts = line.split()
    metric, value = parts[0], (parts[2] if len(parts) > 2 else "")
    if metric == "new_vulnerabilities":
        return f"{value} new vulnerabilit{'y' if value == '1' else 'ies'}"
    if metric == "new_security_hotspots_reviewed":
        return "new security hotspots are not reviewed yet"
    if metric == "new_security_rating":
        return f"security rating of the new code is {RATINGS.get(value.split('.')[0], value)} (must be A)"
    if metric == "new_coverage":
        return f"test coverage of the new code is {value}%"
    if metric == "new_duplicated_lines_density":
        return f"{value}% of the new lines are duplicated"
    if metric == "new_violations":
        return f"{value} new issue{'' if value == '1' else 's'} of any kind"
    return line


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
        return "FAILED", [condition(line.strip()) for line in lines[1:] if line.strip()]
    return "NOT COMPLETED", []


# ------------------------------------------------------------- what it adds
def safe(text, limit=110):
    text = KEY_LIKE.sub("[redacted]", " ".join(str(text).split()))
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def rule_name(rule):
    return str(rule).split(":")[-1].split(".")[-1]


def kind_of_rule(rule, default="Code"):
    if DEPENDENCY_RULE.search(rule):
        return "Dependency"
    if SECRET_RULE.search(rule):
        return "Secret"
    return default


def place_of(finding):
    where = finding.get("location") or {}
    return f"{where.get('path', '')}:{where['startLine']}" if where.get("startLine") else str(where.get("path", ""))


def row(level, kind, what, where, rule):
    return {"level": level, "kind": kind, "what": what, "where": where, "rule": rule}


def from_sdt(out):
    """The scanners' own list of what the pull request adds; None when there is none."""
    try:
        findings = json.load(open(os.path.join(out, "sdt", "findings-new.json")))["findings"]
    except (OSError, ValueError, KeyError):
        return None
    rows = []
    for finding in findings:
        category = str(finding.get("category", "")).lower()
        rule = str((finding.get("rule") or {}).get("id", ""))
        kind = CATEGORIES.get(category) or category.capitalize() or "Code"
        if kind == "Code":
            kind = kind_of_rule(rule)
        rows.append(row(str((finding.get("severity") or {}).get("canonical", "")).lower(), kind,
                        safe(finding.get("message", "")), place_of(finding), rule_name(rule)))
    return rows


def from_sonar(out, host, token, pr_id):
    """Open security issues and unreviewed hotspots SonarQube holds for the pull request; None when it cannot be asked."""
    try:
        key = open(os.path.join(out, "sonar-project-key")).read().strip()
    except OSError:
        return None
    if not (host and token and key):
        return None
    authorization = "Basic " + base64.b64encode(f"{token}:".encode()).decode()
    query = urllib.parse.urlencode
    try:
        issues = get_json(f"{host}/api/issues/search?" + query(
            {"components": key, "pullRequest": pr_id, "resolved": "false", "ps": 500}), authorization).get("issues", [])
        hotspots = get_json(f"{host}/api/hotspots/search?" + query(
            {"project": key, "pullRequest": pr_id, "status": "TO_REVIEW", "ps": 500}), authorization).get("hotspots", [])
    except (urllib.error.URLError, ValueError, OSError) as err:
        log(f"SonarQube was not asked for the pull request's findings ({type(err).__name__}); using the scanners' list")
        return None
    with open(os.path.join(out, "sonar-pull-request.json"), "w") as handle:
        json.dump({"issues": issues, "hotspots": hotspots}, handle, indent=1)

    def place(item):
        path = str(item.get("component", "")).split(":", 1)[-1]
        path = "" if path == key else path
        return f"{path}:{item['line']}" if item.get("line") and path else path

    rows = []
    for issue in issues:
        security = issue.get("type") == "VULNERABILITY" or any(
            impact.get("softwareQuality") == "SECURITY" for impact in issue.get("impacts", []))
        if not security:
            continue  # code smells and bugs are not this scan's business
        rule = str(issue.get("rule", ""))
        rows.append(row(SONAR_SEVERITY.get(issue.get("severity"), "medium"), kind_of_rule(rule),
                        safe(issue.get("message", "")), place(issue), rule_name(rule)))
    for hotspot in hotspots:
        rule = str(hotspot.get("ruleKey", ""))
        rows.append(row(str(hotspot.get("vulnerabilityProbability", "medium")).lower(), kind_of_rule(rule, "To review"),
                        safe(hotspot.get("message", "")), place(hotspot), rule_name(rule)))
    return rows


def rank(level):
    return LEVELS.index(level) if level in LEVELS else len(LEVELS)


def merge_dependencies(rows):
    """One row per package: its advisories side by side, at the highest severity."""
    merged, order = {}, []
    for item in rows:
        if item["kind"] != "Dependency":
            order.append(item)
            continue
        package = PACKAGE.search(item["what"])
        name = f"{package.group(1)} {package.group(2)}" if package else item["what"]
        if name not in merged:
            merged[name] = dict(item, what=name, advisories=[])
            order.append(merged[name])
        entry = merged[name]
        entry["advisories"] += [a for a in ADVISORY.findall(item["what"] + " " + item["rule"]) if a not in entry["advisories"]]
        if rank(item["level"]) < rank(entry["level"]):
            entry["level"] = item["level"]
    for entry in merged.values():
        if entry["advisories"]:
            entry["what"] = f"{entry['what']}: {', '.join(entry['advisories'][:4])}" + (" and more" if len(entry["advisories"]) > 4 else "")
    return order


def one_per_place(rows):
    """Two rules that flag the same line are one thing to fix: the most severe row of a line and type stays,
    and a line that has a finding does not also ask for a review."""
    rows = sorted(rows, key=lambda r: rank(r["level"]))
    decided = {r["where"] for r in rows if r["where"] and r["kind"] != "To review"}
    kept, seen = [], set()
    for item in rows:
        key = (item["where"], item["kind"])
        if item["where"] and (key in seen or (item["kind"] == "To review" and item["where"] in decided)):
            continue
        seen.add(key)
        kept.append(item)
    return kept


def changed_files(src, base):
    """Files the pull request touches; None when git cannot say."""
    if not (src and base):
        return None
    try:
        done = subprocess.run(["git", "-C", src, "diff", "--name-only", f"origin/{base}...HEAD"], capture_output=True,
                              text=True, timeout=60, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return {line.strip() for line in done.stdout.splitlines() if line.strip()}


def fixed(out, touched):
    """Findings on the target branch that this pull request no longer has.

    Only in files the pull request touches, and never secrets: those are found in the history of
    every branch, so their coming and going says nothing about this pull request.
    """
    if touched is None:
        return []
    def load(*path):
        try:
            return [f for f in json.load(open(os.path.join(out, *path)))["findings"] if not f.get("suppression")]
        except (OSError, ValueError, KeyError):
            return None
    before, after = load("base", "findings.json"), load("sdt", "findings.json")
    if before is None or after is None:
        return []
    still = {(f.get("fingerprint") or {}).get("value") for f in after}
    described = []
    for finding in before:
        if (finding.get("fingerprint") or {}).get("value") in still:
            continue
        if str(finding.get("category", "")).lower() in ("secret", "secrets"):
            continue
        if (finding.get("location") or {}).get("path") not in touched:
            continue
        place = place_of(finding)
        described.append(rule_name((finding.get("rule") or {}).get("id", "")) + (f" at `{cell(place)}`" if place else ""))
    return described


def cell(text):
    return str(text).replace("|", "\\|").replace("`", "'").replace("\n", " ")


def body(result, conditions, rows, gone, links, commit, base):
    lines = [f"{MARKER}: {result}", ""]
    if rows is None:
        lines.append("The scan did not produce a list of findings. See the build log.")
    elif not rows:
        lines.append("This pull request adds no new security findings.")
    else:
        rows = sorted(one_per_place(merge_dependencies(rows)), key=lambda r: (rank(r["level"]), r["kind"], r["where"]))
        counts = {}
        for item in rows:
            counts[item["kind"]] = counts.get(item["kind"], 0) + 1
        summary = ", ".join(f"{count} {name.lower()}" for name, count in sorted(counts.items()))
        lines += [f"This pull request adds **{len(rows)}** new security finding{'s' if len(rows) != 1 else ''} ({summary}).", "",
                  "| Severity | Type | Finding | Location |", "| --- | --- | --- | --- |"]
        for item in rows[:MAX_ROWS]:
            where = f"`{cell(item['where'])}`" if item["where"] else ""
            lines.append(f"| {cell(item['level'].capitalize())} | {cell(item['kind'])} | {cell(item['what'] or item['rule'])} | {where} |")
        if len(rows) > MAX_ROWS:
            lines += ["", f"{len(rows) - MAX_ROWS} more in the report."]
    if gone:
        shown = "; ".join(gone[:MAX_FIXED]) + (f"; and {len(gone) - MAX_FIXED} more" if len(gone) > MAX_FIXED else "")
        lines += ["", f"It fixes **{len(gone)}** finding{'s' if len(gone) != 1 else ''} that "
                      f"{'exist' if len(gone) != 1 else 'exists'} on {f'`{cell(base)}`' if base else 'the target branch'}: {shown}."]
    if result == "FAILED" and conditions:
        lines += ["", "Why it failed: " + "; ".join(cell(c) for c in conditions) + "."]
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
    sonar_host = env.get("SONAR_HOST_URL", "").rstrip("/")
    rows = None
    if result != "NOT COMPLETED":
        rows = from_sonar(out, sonar_host, env.get("SONAR_TOKEN", ""), pr_id)
    if rows is None:
        rows = from_sdt(out)

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
    if key and sonar_host:
        links.append(("SonarQube", f"{sonar_host}/dashboard?id={urllib.parse.quote(key)}&pullRequest={urllib.parse.quote(pr_id)}"))
    if build_url:
        links.append(("Build", build_url))

    text = body(result, conditions, rows, fixed(out, changed_files(env.get("SRC", ""), env.get("PR_BASE", ""))), links, scanned_commit(env.get("SRC", "")), env.get("PR_BASE", ""))
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
