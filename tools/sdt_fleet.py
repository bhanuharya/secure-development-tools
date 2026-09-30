#!/usr/bin/env python3
"""Run the Go SDT engine across a Bitbucket Cloud workspace.

The Bitbucket token is used only for API reads and an owner-only Git askpass
file. The ssh transport clones with a private key instead and needs no token at
all. Reports are immutable per fleet run; each repository has its own worktree,
cache and output directory. Sonar is a local, optional report destination.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sdt_knowledge import read_snippet, sensitive_source

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.bitbucket.org/2.0"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CE_TASK_ID = re.compile(r"api/ce/task\?id=([0-9a-fA-F-]{8,})")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        raise ValueError("Bitbucket API redirect refused")


class NoSonarRedirect(NoRedirect):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        raise ValueError("SonarQube API redirect refused")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def env_default(name: str, fallback: Path) -> Path:
    """A flag default taken from the environment, so a worker needs no personal paths."""
    value = os.environ.get(name, "").strip()
    return Path(value) if value else fallback


def repository_inventory(workspace: str, token: str) -> list[dict]:
    """Read all pages; never follow an untrusted pagination URL with the token."""
    url = f"{API}/repositories/{urllib.parse.quote(workspace)}?pagelen=100"
    opener = urllib.request.build_opener(NoRedirect)
    found: list[dict] = []
    seen: set[str] = set()
    while url:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "api.bitbucket.org" or not parsed.path.startswith(f"/2.0/repositories/{workspace}"):
            raise ValueError("Bitbucket returned an unexpected pagination URL")
        if url in seen:
            raise ValueError("Bitbucket pagination loop")
        seen.add(url)
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with opener.open(req, timeout=30) as response:
            page = json.load(response)
        for item in page.get("values", []):
            slug = str(item.get("slug") or "")
            branch = str((item.get("mainbranch") or {}).get("name") or "")
            if NAME.fullmatch(slug):
                found.append({"slug": slug, "branch": branch, "name": str(item.get("name") or slug)})
        url = page.get("next") or ""
    return sorted(found, key=lambda item: item["slug"])


def parse_repo_list(path: Path) -> list[dict]:
    """Read a static inventory: 'slug' or 'slug:branch' per line, blank and '#' lines ignored."""
    found: list[dict] = []
    seen: set[str] = set()
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        branch = ""
        if ":" in entry:
            slug, branch = entry.split(":", 1)
            slug = slug.strip()
            branch = branch.strip()
            if not branch or len(branch) > 200 or any(char.isspace() for char in branch):
                raise ValueError(f"line {number} has an invalid branch name")
        else:
            slug = entry
        if not NAME.fullmatch(slug):
            raise ValueError(f"line {number} is not a Bitbucket repository slug")
        if slug in seen:
            raise ValueError(f"line {number} repeats repository {slug}")
        seen.add(slug)
        found.append({"slug": slug, "branch": branch, "name": slug, "explicit": bool(branch)})
    return found


def parse_ce_task_id(text: str) -> str:
    """Read the Compute Engine task id the scanner prints after a successful upload."""
    match = CE_TASK_ID.search(text or "")
    return match.group(1) if match else ""


def bounded_reason(text: object, secret: str = "") -> str:
    """Flatten a reason to one bounded line; a token must never ride into a report."""
    reason = " ".join(str(text if text is not None else "").split())
    if secret:
        reason = reason.replace(secret, "[redacted]")
    return reason[:300]


def fetch_sonar_task(sonar_url: str, task_id: str, token: str) -> dict:
    parsed = urllib.parse.urlparse(sonar_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("SonarQube host URL must be http(s)")
    url = f"{sonar_url.rstrip('/')}/api/ce/task?id={urllib.parse.quote(task_id, safe='')}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    opener = urllib.request.build_opener(NoSonarRedirect)
    with opener.open(req, timeout=30) as response:
        return json.load(response)


def poll_sonar_task(sonar_url: str, task_id: str, token: str, *, timeout: int,
                    interval: int = 5, sleep=time.sleep, fetch=None) -> tuple[str, str]:
    """Confirm the analysis was imported; scanner exit 0 only means 'uploaded'."""
    fetch = fetch or fetch_sonar_task
    deadline = time.monotonic() + max(timeout, 0)
    observed = "deadline_expired"
    while time.monotonic() < deadline:
        try:
            payload = fetch(sonar_url, task_id, token)
            task = payload.get("task") if isinstance(payload, dict) else None
            status = str((task or {}).get("status") or "")
            if status == "SUCCESS":
                return "imported", ""
            if status in ("FAILED", "CANCELED"):
                return "import_failed", bounded_reason((task or {}).get("errorMessage") or status, token)
            observed = bounded_reason(f"last_status={status or 'unknown'}", token)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            observed = bounded_reason(type(exc).__name__, token)
        sleep(interval)
    return "import_unconfirmed", observed


def base_environment() -> dict[str, str]:
    """Git/child environment with every credential environment variable removed."""
    return {key: value for key, value in os.environ.items() if key not in ("BITBUCKET_ACCESS_TOKEN", "SONAR_TOKEN")}


def git_environment(token: str, directory: Path) -> dict[str, str]:
    """Pass Git a token through an owner-only file, never argv or remote URL."""
    token_path = directory / "bitbucket-token"
    token_path.write_text(token)
    token_path.chmod(0o600)
    helper = directory / "askpass.sh"
    helper.write_text('#!/bin/sh\ncase "$1" in\n  *sername*) printf "x-token-auth\\n" ;;\n  *) cat "$(dirname "$0")/bitbucket-token" ;;\nesac\n')
    helper.chmod(0o700)
    env = base_environment()
    env.update({"GIT_ASKPASS": str(helper), "GIT_TERMINAL_PROMPT": "0"})
    return env


def ssh_command(key: Path) -> str:
    return f"ssh -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes"


def ssh_environment(key: Path) -> dict[str, str]:
    """Authenticate Git with a private key; no token file or askpass helper."""
    env = base_environment()
    env.update({"GIT_SSH_COMMAND": ssh_command(key), "GIT_TERMINAL_PROMPT": "0"})
    return env


def ssh_key_is_private(path: Path) -> bool:
    return path.is_file() and not (path.stat().st_mode & 0o077)


def repository_url(transport: str, workspace: str, slug: str) -> str:
    if transport == "ssh":
        return f"git@bitbucket.org:{workspace}/{slug}.git"
    return f"https://bitbucket.org/{workspace}/{slug}.git"


def clone_arguments(transport: str, workspace: str, slug: str, branch: str, checkout: Path) -> list[str]:
    """An empty branch lets Git check out the remote default branch."""
    args = ["git", "-c", "credential.helper=", "-c", "core.symlinks=false", "clone", "--quiet"]
    if branch:
        args += ["--branch", branch]
    return args + [repository_url(transport, workspace, slug), str(checkout)]


def run_command(args: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False)


# The Java/Kotlin sensors abort a source-only checkout with "No classes were
# found"; findings arrive via externalIssuesReportPaths, so compiled output is
# only needed to keep those built-in sensors alive.
SONAR_COMPILED_SOURCES = ((".java", "sonar.java.binaries"), (".kt", "sonar.kotlin.binaries"))


def has_source_file(checkout: Path, extension: str, directory_limit: int = 2000) -> bool:
    """Bounded walk for one source file of an extension; the cap gives up, never hangs."""
    for seen, (_, _, files) in enumerate(os.walk(checkout), start=1):
        if seen > directory_limit:
            break
        if any(name.endswith(extension) for name in files):
            return True
    return False


def sonar_scan_arguments(scanner: Path, sonar_url: str, project_key: str, project_name: str,
                         issues_report: Path, checkout: Path, classes_dir: Path,
                         branch: str = "") -> list[str]:
    """Scanner run over a source checkout: external issues carry the real findings."""
    command = [str(scanner), f"-Dsonar.host.url={sonar_url}", f"-Dsonar.projectKey={project_key}",
               f"-Dsonar.projectName={project_name}", "-Dsonar.sources=.",
               # An empty test scope keeps "can't be indexed twice" from firing on src/test/java.
               "-Dsonar.tests=", f"-Dsonar.externalIssuesReportPaths={issues_report}"]
    if branch:
        # Community branch plugin (1.22.x) turns this into a named branch view.
        command.append(f"-Dsonar.branch.name={branch}")
    if classes_dir.is_dir():
        command += [f"-D{prop}={classes_dir}" for extension, prop in SONAR_COMPILED_SOURCES
                    if has_source_file(checkout, extension)]
    return command


def scanner_failure_reason(stdout: str, stderr: str, secret: str = "") -> str:
    """Tail of a failed scanner run, token-redacted before slicing so no fragment survives."""
    combined = " ".join(f"{stderr}\n{stdout}".split())
    if secret:
        combined = combined.replace(secret, "[redacted]")
    return bounded_reason(combined[-300:], secret)


def write_review_packet(path: Path, findings: list[dict], source: Path, limit: int = 20) -> int:
    """Prepare a bounded, redacted manual Codex queue, never a verdict."""
    candidates = [finding for finding in findings if finding.get("category") == "sast"
                  and finding.get("confidence") != "high" and not sensitive_source(finding)]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    candidates.sort(key=lambda finding: (severity_order.get((finding.get("severity") or {}).get("canonical"), 5),
                                         (finding.get("fingerprint") or {}).get("value", "")))
    selected = candidates[:limit]
    lines = ["# Manual Codex validation queue", "",
             "Review each finding against the local source and describe the actual source-to-sink path, guards, and counterevidence. This packet is advisory. Do not change SDT's recorded verdict automatically.", "",
             f"Selected {len(selected)} of {len(candidates)} uncertain SAST findings (limit {limit}).", ""]
    for finding in selected:
        loc = finding.get("location") or {}
        rule = finding.get("rule") or {}
        fp = (finding.get("fingerprint") or {}).get("value", "")
        lines.extend([f"## {rule.get('id', 'unknown')} at {loc.get('path', '?')}:{loc.get('startLine', '?')}", "",
                      f"Fingerprint: `{fp}`", "",
                      f"Severity: {(finding.get('severity') or {}).get('canonical', 'unknown')}; confidence: {finding.get('confidence') or 'unknown'}", "",
                      f"Finding: {finding.get('message', '')}", ""])
        snippet = read_snippet(source, str(loc.get("path") or ""), loc.get("startLine"), loc.get("endLine"), context=4, cap_lines=12)
        if snippet:
            lines.extend(["```text", snippet[1], "```", ""])
        lines.extend(["Review: true positive / false positive / needs more context; cite the guard or vulnerable flow and the relevant lines.", ""])
    path.write_text("\n".join(lines))
    return len(selected)


def scan_repository(repo: dict, args: argparse.Namespace, token: str, run_dir: Path, sonar_token: str) -> dict:
    slug = repo["slug"]
    dest = run_dir / "repositories" / slug
    dest.mkdir(parents=True, exist_ok=True)
    dest.chmod(0o700)
    record = {"repository": slug, "branch": repo["branch"], "startedAt": utc_now(),
              "status": "execution_failed", "sonar": "not_run", "findings": 0,
              "artifacts": str(dest.relative_to(run_dir))}
    with tempfile.TemporaryDirectory(prefix=f"sdt-{slug}-", dir=args.work_dir) as tmp:
        temp = Path(tmp)
        env = ssh_environment(args.ssh_key) if args.transport == "ssh" else git_environment(token, temp)
        checkout = temp / "source"
        try:
            clone = run_command(clone_arguments(args.transport, args.workspace, slug, repo["branch"], checkout),
                                cwd=temp, env=env, timeout=args.clone_timeout)
            if clone.returncode:
                record["error"] = "clone_failed"
                return record
            if not record["branch"]:
                # A --repo-list clone follows the remote default branch; record what it landed on.
                head = run_command(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=checkout, env=env, timeout=30)
                if head.returncode == 0:
                    record["branch"] = head.stdout.strip()
            rev = run_command(["git", "rev-parse", "HEAD"], cwd=checkout, env=env, timeout=30)
            if rev.returncode:
                record["error"] = "revision_unavailable"
                return record
            record["commit"] = rev.stdout.strip()
            scan_env = {key: value for key, value in env.items() if key not in ("GIT_ASKPASS", "GIT_TERMINAL_PROMPT", "GIT_SSH_COMMAND")}
            scan_env["SDT_RULES_PACK_DIR"] = str(args.rules)
            scan_env["SDT_DEFAULT_RULES_DIR"] = str(args.rules)
            cache = temp / "cache"
            cache.mkdir()
            scan = run_command([str(args.sdt), "scan", "--config", str(args.scan_config), "--profile", "full", "--output", str(dest), "--cache", str(cache)], cwd=checkout, env=scan_env, timeout=args.scan_timeout)
            record["sdtExitCode"] = scan.returncode
            findings_path = dest / "findings.json"
            if not findings_path.is_file():
                record["error"] = "missing_findings_report"
                return record
            findings = json.loads(findings_path.read_text())
            record["status"] = str(findings.get("status") or "execution_failed")
            record["findings"] = len(findings.get("findings") or [])
            record["runId"] = findings.get("runId", "")
            record["codexQueue"] = write_review_packet(dest / "codex-review.md", findings.get("findings") or [], checkout)
            # Conversion is independent of the SDT exit code. Exit 1 can mean
            # a valid report with policy findings; exit 2-5 remains visible.
            sonar_json = dest / "sonar-external.json"
            converted = run_command([sys.executable, str(ROOT / "tools/sdt_to_sonar.py"), "--from", str(findings_path), "--out", str(sonar_json), "--repo-root", str(checkout)], cwd=checkout, env=scan_env, timeout=60)
            record["sonarExport"] = "ready" if converted.returncode == 0 else "failed"
            pdf = run_command([sys.executable, str(ROOT / "tools/sdt_to_pdf.py"), "--from", str(findings_path), "--manifest", str(dest / "run-manifest.json"), "--out", str(dest / "security-report.pdf"), "--project", f"{args.workspace}/{slug}", "--src-root", str(checkout)], cwd=checkout, env=scan_env, timeout=120)
            record["pdf"] = "ready" if pdf.returncode == 0 else "failed"
            if args.sonar and sonar_token and converted.returncode == 0:
                sonar_env = {**scan_env, "SONAR_TOKEN": sonar_token}
                suffix = hashlib.sha256(f"{args.workspace}/{slug}".encode()).hexdigest()[:10]
                project_key = (f"sdt_{args.workspace}_{slug}".replace(".", "_").replace("-", "_")[:160] + "_" + suffix)
                sonar = run_command(sonar_scan_arguments(args.sonar_scanner, args.sonar_url, project_key,
                                                         f"{args.workspace}/{slug}", sonar_json, checkout,
                                                         args.sonar_classes,
                                                         branch=record["branch"] if (args.sonar_branch and repo.get("explicit")) else ""),
                                    cwd=checkout, env=sonar_env, timeout=args.sonar_timeout)
                record["sonarProjectKey"] = project_key
                if sonar.returncode:
                    record["sonar"] = "failed"
                    record["sonarError"] = scanner_failure_reason(sonar.stdout, sonar.stderr, sonar_token)
                else:
                    # Uploading is not importing: wait for the Compute Engine task the scanner names.
                    task_id = parse_ce_task_id(sonar.stdout) or parse_ce_task_id(sonar.stderr)
                    if not task_id:
                        record["sonar"] = "import_unconfirmed"
                        record["sonarError"] = "no_ce_task_id"
                    else:
                        state, reason = poll_sonar_task(args.sonar_url, task_id, sonar_token, timeout=args.sonar_poll_timeout)
                        record["sonar"] = state
                        if reason:
                            record["sonarError"] = reason
            elif args.sonar:
                record["sonar"] = "missing_token_or_export"
        except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            record["error"] = type(exc).__name__
        finally:
            record["completedAt"] = utc_now()
    return record


def write_fleet_manifest(path: Path, run_id: str, workspace: str, records: list[dict], selected: int) -> None:
    manifest = {"schemaVersion": "sdt/fleet/v1", "runId": run_id, "workspace": workspace,
                "generatedAt": utc_now(), "selectedRepositories": selected,
                "repositoryCount": len(records),
                "repositories": sorted(records, key=lambda record: record["repository"])}
    pending = path.with_suffix(".json.tmp")
    pending.write_text(json.dumps(manifest, indent=2) + "\n")
    pending.replace(path)


def build_parser() -> argparse.ArgumentParser:
    """Every machine-local default reads an env var first, so a container worker
    can be configured without carrying this lab's home-directory paths."""
    parser = argparse.ArgumentParser(description="Central Bitbucket Cloud SDT scan")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--repo", action="append", default=[], help="restrict to named repositories; repeat for a pilot")
    parser.add_argument("--transport", choices=("token", "ssh"), default="token",
                        help="token reads the Bitbucket API and clones over HTTPS; ssh clones with a private key and needs no token")
    parser.add_argument("--repo-list", type=Path, help="file of repository slugs to scan; skips the Bitbucket API inventory")
    parser.add_argument("--ssh-key", type=Path, default=env_default("SDT_FLEET_SSH_KEY", Path("/home/wishnu/.ssh/bitbucket_sdt")),
                        help="private key for the ssh transport")
    parser.add_argument("--bitbucket-token-file", type=Path, help="read the Bitbucket token from a private file")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--list", action="store_true", help="list accessible repositories without cloning")
    parser.add_argument("--output", type=Path, default=env_default("SDT_FLEET_OUTPUT", ROOT / "reports" / "fleet"),
                        help="root of fleet run artifacts (default: $SDT_FLEET_OUTPUT, else <repo>/reports/fleet)")
    parser.add_argument("--work-dir", type=Path, default=env_default("SDT_FLEET_WORK", Path(tempfile.gettempdir())),
                        help="parent of the per-repository checkouts (default: $SDT_FLEET_WORK, else the system temp dir)")
    parser.add_argument("--sdt", type=Path, default=env_default("SDT_FLEET_SDT_BIN", ROOT / "sdt"),
                        help="SDT engine binary (default: $SDT_FLEET_SDT_BIN, else <repo>/sdt)")
    parser.add_argument("--rules", type=Path, default=env_default("SDT_FLEET_RULES", ROOT / "rules" / "opengrep-rules"),
                        help="rule pack directory (default: $SDT_FLEET_RULES, else <repo>/rules/opengrep-rules)")
    parser.add_argument("--scan-config", type=Path,
                        default=env_default("SDT_FLEET_SCAN_CONFIG", ROOT / "examples" / "fleet" / "scan-config.yaml"),
                        help="scan configuration (default: $SDT_FLEET_SCAN_CONFIG, else <repo>/examples/fleet/scan-config.yaml)")
    parser.add_argument("--sonar", action="store_true", help="submit local Sonar analysis per repository")
    parser.add_argument("--sonar-url", default=os.environ.get("SDT_FLEET_SONAR_URL", "http://localhost:9000"),
                        help="override with SDT_FLEET_SONAR_URL")
    parser.add_argument("--sonar-scanner", type=Path,
                        default=env_default("SDT_FLEET_SONAR_SCANNER",
                                            Path("/home/wishnu/sd-lab/scanner/sonar-scanner-6.2.1.4610-linux-x64/bin/sonar-scanner")),
                        help="sonar-scanner launcher (default: $SDT_FLEET_SONAR_SCANNER)")
    parser.add_argument("--sonar-token-file", type=Path,
                        default=env_default("SDT_FLEET_SONAR_TOKEN_FILE", Path("/home/wishnu/sd-lab/.sonar-token")),
                        help="owner-only Sonar token file (default: $SDT_FLEET_SONAR_TOKEN_FILE)")
    parser.add_argument("--sonar-classes", type=Path,
                        default=env_default("SDT_FLEET_SONAR_CLASSES", Path("/home/wishnu/sdt-fleet/sonar-dummy-classes")),
                        help="dummy compiled classes that keep the Java/Kotlin sensors alive on source-only checkouts "
                             "(default: $SDT_FLEET_SONAR_CLASSES)")
    parser.add_argument("--triage", type=Path, help="CSV verdict ledger keyed by repository and fingerprint")
    parser.add_argument("--clone-timeout", type=int, default=900)
    parser.add_argument("--scan-timeout", type=int, default=3600)
    parser.add_argument("--sonar-timeout", type=int, default=1800)
    parser.add_argument("--sonar-poll-timeout", type=int, default=600,
                        help="total time per repository to wait for SonarQube to import the analysis")
    parser.add_argument("--sonar-branch", action="store_true",
                        help="submit explicitly requested branches (slug:branch lines) as sonar.branch.name; "
                             "default-branch scans never pass it, so Sonar keeps them as the project main")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not NAME.fullmatch(args.workspace) or any(not NAME.fullmatch(name) for name in args.repo):
        parser.error("workspace and repo names must be Bitbucket slugs")
    if args.jobs < 1 or args.jobs > 8 or args.limit < 0:
        parser.error("jobs must be 1–8 and limit must be nonnegative")
    args.sdt = args.sdt.resolve()
    args.rules = args.rules.resolve()
    args.scan_config = args.scan_config.resolve()
    args.sonar_scanner = args.sonar_scanner.resolve()
    args.sonar_classes = args.sonar_classes.resolve()
    args.work_dir = args.work_dir.resolve()
    if not args.work_dir.is_dir():
        parser.error("work-dir must exist")
    token = ""
    if args.transport == "ssh":
        args.ssh_key = args.ssh_key.resolve()
        if not ssh_key_is_private(args.ssh_key):
            parser.error("--ssh-key must be a private key file that is not group or world readable")
    else:
        try:
            token = args.bitbucket_token_file.read_text().strip() if args.bitbucket_token_file else os.getenv("BITBUCKET_ACCESS_TOKEN", "")
        except OSError:
            parser.error("Bitbucket token file could not be read")
        if not token:
            parser.error("BITBUCKET_ACCESS_TOKEN or --bitbucket-token-file is required")
    if not args.list and (not args.sdt.is_file() or not args.scan_config.is_file() or not args.rules.is_dir()):
        parser.error("SDT binary, scan config, and rule pack must be present")
    if args.sonar and not args.sonar_scanner.is_file():
        parser.error("SonarScanner is not present")
    if args.repo_list:
        try:
            repos = parse_repo_list(args.repo_list)
        except (OSError, ValueError) as exc:
            parser.error(f"--repo-list: {exc}")
    else:
        try:
            repos = repository_inventory(args.workspace, token)
        except (OSError, ValueError, urllib.error.HTTPError) as exc:
            print(f"Bitbucket inventory failed: {type(exc).__name__}", file=sys.stderr)
            return 2
    if args.repo:
        wanted = set(args.repo)
        repos = [repo for repo in repos if repo["slug"] in wanted]
        if len(repos) != len(wanted):
            print("one or more requested repositories are unavailable", file=sys.stderr)
            return 2
    if args.limit:
        repos = repos[:args.limit]
    if not repos:
        print("No repositories selected; refusing an empty fleet run", file=sys.stderr)
        return 2
    if args.list:
        for repo in repos:
            print(f"{repo['slug']}\t{repo['branch']}")
        return 0
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = args.output.resolve() / run_id
    run_dir.mkdir(parents=True)
    run_dir.chmod(0o700)
    try:
        sonar_token = args.sonar_token_file.read_text().strip() if args.sonar and args.sonar_token_file.is_file() else os.getenv("SONAR_TOKEN", "")
    except OSError:
        print("Sonar token file could not be read", file=sys.stderr)
        return 2
    if args.sonar and not sonar_token:
        print("Sonar analysis token required (SONAR_TOKEN or --sonar-token-file)", file=sys.stderr)
        return 2
    records: list[dict] = []
    manifest_path = run_dir / "fleet-manifest.json"
    write_fleet_manifest(manifest_path, run_id, args.workspace, records, len(repos))
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(scan_repository, repo, args, token, run_dir, sonar_token): repo["slug"] for repo in repos}
        for future in concurrent.futures.as_completed(futures):
            try:
                record = future.result()
            except Exception as exc:
                record = {"repository": futures[future], "status": "execution_failed", "error": type(exc).__name__,
                          "findings": 0, "sonar": "not_run", "completedAt": utc_now()}
            records.append(record)
            print(f"{record['repository']}: {record['status']} findings={record['findings']} sonar={record['sonar']}")
            write_fleet_manifest(manifest_path, run_id, args.workspace, records, len(repos))
    report_args = [sys.executable, str(ROOT / "tools/sdt_fleet_report.py"), "--from", str(manifest_path)]
    if args.triage:
        report_args += ["--triage", str(args.triage.resolve())]
    report_env = {key: value for key, value in os.environ.items() if key not in ("BITBUCKET_ACCESS_TOKEN", "SONAR_TOKEN")}
    exported = run_command(report_args, cwd=ROOT, env=report_env, timeout=180)
    print(f"Fleet artifacts: {run_dir}")
    if exported.returncode:
        print("Fleet report export failed", file=sys.stderr)
        return 3
    healthy = all(record["status"] in ("passed", "policy_failed") and record.get("pdf") == "ready"
                  and (not args.sonar or record.get("sonar") == "imported") for record in records)
    return 0 if healthy else 4


if __name__ == "__main__":
    raise SystemExit(main())
