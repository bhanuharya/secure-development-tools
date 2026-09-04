"""Command-line client for the Secure SDLC Control Plane.

Designed for both humans and automation: every command prints a table by
default and complete JSON with ``--json``.

Configuration (environment):
    SCP_URL          base URL of the control plane (default http://127.0.0.1:8000)
    SCP_AUTH_USER / SCP_AUTH_PASS   HTTP Basic credentials
    SCP_API_TOKEN    Bearer token (alternative to Basic)

Examples:
    scp status
    scp projects list
    scp scan zip app.zip --preset full --watch
    scp scan folder /srv/repos/my-app --preset iac --json
    scp findings list --severity-gte high --status new
    scp findings bulk-triage 12 13 14 --status false_positive --reason "fp"
"""

from __future__ import annotations

import argparse
import json as jsonlib
import os
import sys
import time

import httpx

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("new", "triaged", "fixed", "false_positive", "accepted_risk")
PRESETS = ("full", "sast", "dependencies", "secrets", "iac")


class Client:
    def __init__(self, base_url: str) -> None:
        headers = {"Accept": "application/json"}
        user = os.getenv("SCP_AUTH_USER", "")
        password = os.getenv("SCP_AUTH_PASS", "")
        token = os.getenv("SCP_API_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif user or password:
            import base64

            raw = base64.b64encode(f"{user}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {raw}"
        self.http = httpx.Client(base_url=base_url, headers=headers, timeout=60)

    def request(self, method: str, path: str, **kw) -> httpx.Response:
        resp = self.http.request(method, path, **kw)
        if resp.status_code in (401, 403):
            _die(f"not authorized ({resp.status_code}): check SCP_URL / credentials")
        try:
            body = resp.json()
        except ValueError:
            body = None
        if not resp.is_success:
            detail = (body or {}).get("detail") if isinstance(body, dict) else None
            _die(f"{method} {path} failed: {detail or resp.status_code}")
        return resp

    def get(self, path: str):
        return self.request("GET", path).json()

    def post(self, path: str, data=None):
        return self.request("POST", path, json=data or {}).json()

    def patch(self, path: str, data):
        return self.request("PATCH", path, json=data).json()

    def download(self, url: str, dest: str) -> None:
        with self.http.stream("GET", url) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as fh:
                for chunk in resp.iter_bytes():
                    fh.write(chunk)


def _die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


def _emit(data, as_json: bool, render=None) -> None:
    if as_json:
        print(jsonlib.dumps(data, indent=2, default=str))
    elif render:
        render(data)
    else:
        print(jsonlib.dumps(data, indent=2, default=str))


def _table(rows: list[dict], columns: list[str]) -> None:
    if not rows:
        print("(none)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns}
    header = "  ".join(c.ljust(widths[c]) for c in columns)
    print(header)
    print("  ".join("-" * widths[c] for c in columns))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in columns))


# ---------------------------------------------------------------- commands

def cmd_status(args, client: Client) -> None:
    health = client.get("/api/health")
    scanners = client.get("/api/scanners/status")

    def render(_):
        print(f"service: {health['service']} v{health['version']} ({health['status']})")
        rows = []
        for name, info in scanners.items():
            label = "available" if info.get("available") else "unavailable"
            extra = info.get("implementation") or ""
            if name == "zap":
                label = "reachable" if info.get("reachable") else "not reachable"
                extra = info.get("url", "")
            rows.append({"engine": name, "state": label, "version": info.get("version", ""), "note": extra})
        _table(rows, ["engine", "state", "version", "note"])

    _emit({"health": health, "scanners": scanners}, args.json, render)


def cmd_projects_list(args, client: Client) -> None:
    projects = client.get("/api/projects")
    _emit(projects, args.json, lambda ps: _table(
        [{"id": p["id"], "name": p["name"], "repo": f"{p['workspace']}/{p['repo_slug']}" if p["workspace"] else "(standalone)", "branch": p["default_branch"]} for p in projects],
        ["id", "name", "repo", "branch"],
    ))


def cmd_scans_list(args, client: Client) -> None:
    params = {}
    if args.project:
        params["project_id"] = args.project
    if args.status:
        params["status"] = args.status
    query = "&".join(f"{k}={v}" for k, v in params.items())
    scans = client.get(f"/api/scans?{query}")
    _emit(scans, args.json, lambda ss: _table(
        [{"id": s["id"], "project": s["project_id"], "type": s["scan_type"], "ref": s["ref_name"],
          "engines": s["engines"], "status": s["status"]} for s in scans],
        ["id", "project", "type", "ref", "engines", "status"],
    ))


def cmd_scan_repo(args, client: Client) -> None:
    body = {
        "project_id": args.project_id,
        "scan_type": args.scan_type,
        "ref_type": "pr" if args.pr else "branch",
        "ref_name": args.pr or args.branch or "",
    }
    if args.engines:
        body["engines"] = args.engines.split(",")
    scan = client.post("/api/scans", body)
    _after_scan(scan, args, client)


def cmd_scan_zip(args, client: Client) -> None:
    if not os.path.isfile(args.file):
        _die(f"no such file: {args.file}")
    data = {"preset": args.preset or "", "name": args.name or ""}
    if args.engines:
        data.update({"preset": "custom", "scan_type": "full", "engines": args.engines.split(",")})
    with open(args.file, "rb") as fh:
        files = {"file": (os.path.basename(args.file), fh, "application/zip")}
        resp = client.request("POST", "/api/uploads/scan", data=data, files=files)
    scan = resp.json()
    _after_scan(scan, args, client)


def cmd_scan_folder(args, client: Client) -> None:
    body = {"path": args.path, "preset": args.preset or "", "name": args.name or ""}
    if args.engines:
        body.update({"preset": "custom", "scan_type": "full", "engines": args.engines.split(",")})
    scan = client.post("/api/uploads/folder", body)
    _after_scan(scan, args, client)


def cmd_scan_dast(args, client: Client) -> None:
    """Register a DAST target; with --approve, also approve it and start a scan.

    Approval is a deliberate second step by design: registering a target never
    launches anything on its own.
    """
    target = client.post("/api/uploads/dast", {"url": args.url, "name": args.name or ""})
    if not getattr(args, "approve", False):
        _emit(target, getattr(args, "json", False), lambda t: print(
            f"target {t['id']} registered (project {t['project_id']}) — not approved.\n"
            f"Approve it (scp scan dast {args.url} --approve) before scanning."
        ))
        return
    client.post(
        f"/api/targets/{target['id']}/approve",
        {"reason": args.reason or "", "production_ack": bool(args.production_ack)},
    )
    scan = client.post("/api/scans", {
        "project_id": target["project_id"],
        "scan_type": "dast",
        "dast_target": target["id"],
    })
    _after_scan(scan, args, client)


def _after_scan(scan: dict, args, client: Client) -> None:
    def render(_):
        print(f"scan {scan['id']} started (status: {scan['status']})")

    _emit(scan, getattr(args, "json", False), render)
    if getattr(args, "watch", False):
        _watch(scan["id"], client)


def cmd_watch(args, client: Client) -> None:
    _watch(args.scan_id, client)


def _watch(scan_id: int, client: Client) -> None:
    last_states: dict = {}
    while True:
        scan = client.get(f"/api/scans/{scan_id}")
        try:
            states = jsonlib.loads(scan.get("engine_statuses") or "{}")
        except ValueError:
            states = {}
        for eng, st in states.items():
            line = f"  {eng}: {st.get('state', '?')}"
            if st.get("reason"):
                line += f" ({st['reason'][:80]})"
            if last_states.get(eng) != line:
                print(line)
                last_states[eng] = line
        if scan["status"] in ("succeeded", "failed", "aborted"):
            summary = jsonlib.loads(scan.get("summary") or "{}")
            print(f"scan {scan_id} {scan['status']}: {summary.get('total', 0)} findings")
            if scan.get("error"):
                print(f"error: {scan['error']}")
            return
        time.sleep(2)


def cmd_findings_list(args, client: Client) -> None:
    params = []
    if args.scan:
        params.append(f"scan_id={args.scan}")
    if args.project:
        params.append(f"project_id={args.project}")
    if args.status:
        params.append(f"status={args.status}")
    if args.severity:
        params.append(f"severity={args.severity}")
    if args.severity_gte:
        params.append(f"severity_gte={args.severity_gte}")
    if args.tool:
        params.append(f"tool={args.tool}")
    if args.q:
        params.append(f"q={httpx.QueryParams({'q': args.q})['q']}")
    if args.limit:
        params.append(f"limit={args.limit}")
    findings = client.get("/api/findings?" + "&".join(params))
    _emit(findings, args.json, lambda fs: _table(
        [{"id": f["id"], "sev": f["severity"], "tool": f["tool"], "rule": f["rule_id"],
          "location": f"{f['file_path']}:{f['line_start'] or ''}", "status": f["status"]} for f in findings],
        ["id", "sev", "tool", "rule", "location", "status"],
    ))


def cmd_findings_triage(args, client: Client) -> None:
    if args.status not in STATUSES:
        _die(f"invalid status; expected one of {STATUSES}")
    result = client.patch(f"/api/findings/{args.finding_id}", {"status": args.status, "reason": args.reason})
    _emit(result, args.json, lambda _: print(f"finding {args.finding_id} -> {args.status}"))


def cmd_findings_bulk_triage(args, client: Client) -> None:
    if args.status not in STATUSES:
        _die(f"invalid status; expected one of {STATUSES}")
    result = client.post("/api/findings/bulk-status", {"ids": args.ids, "status": args.status, "reason": args.reason})
    _emit(result, args.json, lambda r: print(
        f"changed {r['changed']} finding(s)" + (f"; missing: {r['missing']}" if r["missing"] else "")
    ))


def cmd_report(args, client: Client) -> None:
    if args.kind == "scan":
        meta = client.post(f"/api/reports/scan/{args.id}", {})
    else:
        meta = client.post(f"/api/reports/project/{args.id}", {"pr_only": False})
    dest = args.output or os.path.basename(meta["file"]) or f"report-{args.id}.pdf"
    client.download(meta["file"], dest)
    print(f"saved {dest}")


def client_base() -> str:
    return os.getenv("SCP_URL", "http://127.0.0.1:8000").rstrip("/")


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="scp", description="Secure SDLC Control Plane CLI")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status", help="service + engine availability")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("projects", help="project operations")
    ps = s.add_subparsers(dest="sub", required=True)
    pl = ps.add_parser("list")
    pl.set_defaults(fn=cmd_projects_list)

    s = sub.add_parser("scans", help="list scans")
    sl = s.add_subparsers(dest="sub", required=True)
    lst = sl.add_parser("list")
    lst.add_argument("--project", type=int)
    lst.add_argument("--status", choices=["pending", "running", "succeeded", "failed", "aborted"])
    lst.set_defaults(fn=cmd_scans_list)

    s = sub.add_parser("scan", help="start a scan")
    ss = s.add_subparsers(dest="sub", required=True)

    repo = ss.add_parser("repo", help="scan a Bitbucket project")
    repo.add_argument("project_id", type=int)
    repo.add_argument("--branch", default="")
    repo.add_argument("--pr", default="", help="PR id")
    repo.add_argument("--scan-type", default="sast",
                      choices=["sast", "sca", "secrets", "iac", "dast"])
    repo.add_argument("--engines", default="", help="comma-separated engine names")
    repo.add_argument("--watch", action="store_true")
    repo.set_defaults(fn=cmd_scan_repo)

    z = ss.add_parser("zip", help="scan an uploaded ZIP archive")
    z.add_argument("file")
    z.add_argument("--preset", choices=PRESETS, default="full")
    z.add_argument("--engines", default="")
    z.add_argument("--name", default="")
    z.add_argument("--watch", action="store_true")
    z.set_defaults(fn=cmd_scan_zip)

    f = ss.add_parser("folder", help="scan a local folder on the host")
    f.add_argument("path")
    f.add_argument("--preset", choices=PRESETS, default="full")
    f.add_argument("--engines", default="")
    f.add_argument("--name", default="")
    f.add_argument("--watch", action="store_true")
    f.set_defaults(fn=cmd_scan_folder)

    d = ss.add_parser("dast", help="register a DAST target (add --approve to approve and scan)")
    d.add_argument("url")
    d.add_argument("--name", default="")
    d.add_argument("--approve", action="store_true",
                   help="approve the target and immediately start a scan")
    d.add_argument("--production-ack", action="store_true",
                   help="acknowledge scanning a production target (required with --approve for prod)")
    d.add_argument("--reason", default="", help="approval reason (recorded in the audit trail)")
    d.add_argument("--watch", action="store_true")
    d.set_defaults(fn=cmd_scan_dast)

    s = sub.add_parser("watch", help="follow a scan until it finishes")
    s.add_argument("scan_id", type=int)
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("findings", help="finding operations")
    fs = s.add_subparsers(dest="sub", required=True)
    fl = fs.add_parser("list")
    fl.add_argument("--scan", type=int)
    fl.add_argument("--project", type=int)
    fl.add_argument("--status", choices=STATUSES)
    fl.add_argument("--severity", choices=SEVERITIES)
    fl.add_argument("--severity-gte", choices=SEVERITIES)
    fl.add_argument("--tool")
    fl.add_argument("--q")
    fl.add_argument("--limit", type=int, default=500)
    fl.set_defaults(fn=cmd_findings_list)

    ft = fs.add_parser("triage")
    ft.add_argument("finding_id", type=int)
    ft.add_argument("status", choices=STATUSES)
    ft.add_argument("--reason", default="")
    ft.set_defaults(fn=cmd_findings_triage)

    fb = fs.add_parser("bulk-triage")
    fb.add_argument("ids", nargs="+", type=int)
    fb.add_argument("status", choices=STATUSES)
    fb.add_argument("--reason", default="")
    fb.set_defaults(fn=cmd_findings_bulk_triage)

    s = sub.add_parser("report", help="download a PDF report")
    s.add_argument("kind", choices=["scan", "project"])
    s.add_argument("id", type=int)
    s.add_argument("-o", "--output", default="")
    s.set_defaults(fn=cmd_report)

    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    client = Client(client_base())
    args.fn(args, client)


if __name__ == "__main__":
    main()
