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
