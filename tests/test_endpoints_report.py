"""The Endpoints section of the SAST .docx report (T10)."""

import json
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import sdt_to_docx  # noqa: E402

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

INVENTORY = {
    "schema": "sdt-endpoints/v1",
    "root": ".",
    "routes": [
        {"service": ".", "framework": "gin", "method": "POST", "path": "/api/notifications",
         "handler": "sendNotification", "file": "main.go", "line": 16, "protection": "public",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "PUT", "path": "/api/admin/roles/{id}",
         "handler": "updateRole", "file": "main.go", "line": 24, "protection": "authenticated",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "GET", "path": "/api/admin/users",
         "handler": "listUsers", "file": "main.go", "line": 23, "protection": "public",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "POST", "path": "/api/orders",
         "handler": "createOrder", "file": "main.go", "line": 10, "protection": "authenticated",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "POST", "path": "/api/v1/registration",
         "handler": "register", "file": "main.go", "line": 31, "protection": "public",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "GET", "path": "/api/health",
         "handler": "health", "file": "main.go", "line": 7, "protection": "public",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "POST", "path": "/api/jobs",
         "handler": "startJob", "file": "main.go", "line": 30, "protection": "unknown",
         "confidence": "low", "evidence": []},
        {"service": ".", "framework": "gin", "method": "GET", "path": "/api/admin/audit",
         "handler": "auditLog", "file": "main.go", "line": 40, "protection": "role",
         "confidence": "high", "evidence": []},
    ],
    "summary": {"public": 4, "authenticated": 2, "role": 1, "unknown": 1},
}


def _inventory(tmp_path):
    path = tmp_path / "endpoints.json"
    path.write_text(json.dumps(INVENTORY))
    return path


def _text(path):
    with zipfile.ZipFile(path) as archive:
        root = ElementTree.fromstring(archive.read("word/document.xml"))
    return "".join(node.text or "" for node in root.iter(W + "t"))


def _report(tmp_path, endpoints=None):
    out = tmp_path / "report.docx"
    report = sdt_to_docx.Report("app", "example/app", "branch main", "", "abc1234",
                                "OpenGrep + Gitleaks + Trivy", [], [], [], [],
                                sdt_to_docx.date(2026, 11, 11), endpoints=endpoints)
    sdt_to_docx.write_docx(report, None, out, logo=None)
    return _text(out)


def test_inventory_is_read_and_the_section_lists_the_routes_that_matter(tmp_path):
    inventory = sdt_to_docx.load_endpoints(_inventory(tmp_path))
    assert sdt_to_docx.protection_rows(inventory) == [
        ["Public", 4], ["Authenticated", 2], ["Role", 1], ["Denied", 0], ["Unknown", 1], ["TOTAL", 8]]
    # Onboarding is public by design and is not listed as an unprotected route.
    assert [r.path for r in inventory.public_state_changing()] == ["/api/notifications"]
    # A public sensitive route comes first even when the inventory lists it last.
    assert [r.path for r in inventory.sensitive_to_review()] == ["/api/admin/users", "/api/admin/roles/{id}"]
    assert [r.path for r in inventory.sensitive_with_role()] == ["/api/admin/audit"]

    text = _report(tmp_path, inventory)
    assert text.count("4. Endpoints") == 2  # contents entry and heading
    assert text.rindex("3. Dependencies & Configuration (Trivy)") < text.rindex("4. Endpoints") \
        < text.rindex("How Priority Is Set")
    for expected in ("Routes per protection", "Public state-changing routes", "Sensitive routes",
                     "POST", "/api/notifications", "main.go:16",
                     "GET", "/api/admin/users", "PUT", "/api/admin/roles/{id}", "authenticated",
                     "main.go:23", "main.go:24",
                     "1 sensitive route requires a role and is not listed"):
        assert expected in text
    # Unknown routes are counted and never listed as a route to review.
    assert "startJob" not in text
    assert "/api/v1/registration" not in text
    # A role already protects this sensitive route, so the table leaves it out.
    assert "/api/admin/audit" not in text


def test_a_role_protected_sensitive_route_replaces_the_table_with_one_sentence(tmp_path):
    inventory = {
        "schema": "sdt-endpoints/v1",
        "root": ".",
        "routes": [{"service": ".", "framework": "gin", "method": "GET", "path": "/api/admin/audit",
                    "handler": "auditLog", "file": "main.go", "line": 40, "protection": "role",
                    "confidence": "high", "evidence": []}],
        "summary": {"role": 1},
    }
    path = tmp_path / "endpoints.json"
    path.write_text(json.dumps(inventory))

    text = _report(tmp_path, sdt_to_docx.load_endpoints(path))
    assert "No sensitive route needs review; 1 sensitive route requires a role and is not listed." in text
    assert "/api/admin/audit" not in text


def test_section_is_absent_without_an_inventory(tmp_path):
    text = _report(tmp_path)
    assert "Endpoints" not in text


def test_main_reads_endpoints_json_beside_findings(tmp_path, monkeypatch):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({"findings": []}))
    _inventory(tmp_path)
    out = tmp_path / "report.docx"
    monkeypatch.setattr(sys, "argv", ["sdt_to_docx.py", "--findings", str(findings), "--out", str(out)])
    assert sdt_to_docx.main() == 0
    assert "Routes per protection" in _text(out)


def _scan(tmp_path, monkeypatch, routes, previous=None):
    """One report run over findings.json + endpoints.json; returns (text, state path)."""
    run = tmp_path / f"run{len(list(tmp_path.glob('run*')))}"
    run.mkdir()
    (run / "findings.json").write_text(json.dumps({"findings": []}))
    (run / "endpoints.json").write_text(json.dumps(dict(INVENTORY, routes=routes, summary={})))
    out, state = run / "report.docx", run / "report-state.json"
    argv = ["sdt_to_docx.py", "--findings", str(run / "findings.json"), "--out", str(out), "--state-out", str(state)]
    if previous:
        argv += ["--previous-state", str(previous)]
    monkeypatch.setattr(sys, "argv", argv)
    assert sdt_to_docx.main() == 0
    return _text(out), state


def test_compare_endpoints_reports_new_weaker_and_removed_routes():
    before = [{"key": ".|POST|/api/orders", "protection": "role", "file": "a.go", "line": 1},
              {"key": ".|GET|/api/old", "protection": "public", "file": "a.go", "line": 2},
              {"key": ".|GET|/api/reports", "protection": "authenticated", "file": "a.go", "line": 3}]
    now = [{"key": ".|POST|/api/orders", "protection": "authenticated", "file": "a.go", "line": 9},
           {"key": ".|GET|/api/reports", "protection": "role", "file": "a.go", "line": 3},
           {"key": ".|POST|/api/transfer", "protection": "public", "file": "b.go", "line": 4},
           {"key": ".|GET|/api/ledger", "protection": "unknown", "file": "a.go", "line": 5}]
    before.append({"key": ".|GET|/api/ledger", "protection": "authenticated", "file": "a.go", "line": 5})
    changes = sdt_to_docx.compare_endpoints(now, before)
    assert [e["key"] for e in changes["added"]] == [".|POST|/api/transfer"]
    assert [(e["key"], e["before"], e["protection"]) for e in changes["weaker"]] == [
        (".|POST|/api/orders", "role", "authenticated")]  # stronger protection is not listed
    assert changes["removed"] == 1
    assert changes["uncertain"] == 1  # authenticated -> unknown is counted, not listed as weaker


def test_second_scan_lists_new_public_and_weaker_routes(tmp_path, monkeypatch):
    first = [dict(r) for r in INVENTORY["routes"]]
    text, state = _scan(tmp_path, monkeypatch, first)
    assert "No earlier inventory to compare with" in text
    saved = json.loads(state.read_text())["endpoints"]
    assert {"key": ".|POST|/api/orders", "protection": "authenticated", "file": "main.go", "line": 10} in saved
    assert all(set(e) == {"key", "protection", "file", "line"} for e in saved)  # no code, no evidence

    second = [dict(r) for r in first if r["path"] != "/api/health"]
    for r in second:
        if r["path"] == "/api/admin/audit":
            r["protection"] = "authenticated"  # a role check was lost
    second.append({"service": ".", "framework": "gin", "method": "POST", "path": "/api/payouts", "handler": "payout",
                   "file": "pay.go", "line": 5, "protection": "public", "confidence": "high", "evidence": []})
    text, _ = _scan(tmp_path, monkeypatch, second, previous=state)
    assert "1 new route (1 public), 1 route with weaker protection, 1 route removed." in text
    assert "/api/payouts" in text and "pay.go:5" in text
    assert "/api/admin/auditroleauthenticated" in text  # Before / Now cells of the weaker route


def test_served_path_is_shown_but_matching_uses_the_application_path(tmp_path):
    routes = [{"service": ".", "framework": "spring-mvc", "method": "POST", "path": "/api/admin/refunds",
               "externalPath": "/orders-service/api/admin/refunds", "handler": "refund", "file": "Orders.java",
               "line": 11, "protection": "public", "confidence": "high", "evidence": []}]
    path = tmp_path / "endpoints.json"
    path.write_text(json.dumps(dict(INVENTORY, routes=routes, summary={"public": 1})))
    inv = sdt_to_docx.load_endpoints(path)
    assert [r.path for r in inv.sensitive()] == ["/api/admin/refunds"]  # the path lists see the application path
    text = _report(tmp_path, inv)
    assert "/orders-service/api/admin/refunds" in text

