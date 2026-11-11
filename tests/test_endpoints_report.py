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
        {"service": ".", "framework": "gin", "method": "GET", "path": "/api/admin/users",
         "handler": "listUsers", "file": "main.go", "line": 23, "protection": "public",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "PUT", "path": "/api/admin/roles/{id}",
         "handler": "updateRole", "file": "main.go", "line": 24, "protection": "authenticated",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "POST", "path": "/api/orders",
         "handler": "createOrder", "file": "main.go", "line": 10, "protection": "authenticated",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "GET", "path": "/api/health",
         "handler": "health", "file": "main.go", "line": 7, "protection": "public",
         "confidence": "high", "evidence": []},
        {"service": ".", "framework": "gin", "method": "POST", "path": "/api/jobs",
         "handler": "startJob", "file": "main.go", "line": 30, "protection": "unknown",
         "confidence": "low", "evidence": []},
    ],
    "summary": {"public": 3, "authenticated": 2, "unknown": 1},
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
        ["Public", 3], ["Authenticated", 2], ["Role", 0], ["Denied", 0], ["Unknown", 1], ["TOTAL", 6]]
    assert [r.path for r in inventory.public_state_changing()] == ["/api/notifications"]
    assert [r.path for r in inventory.sensitive()] == ["/api/admin/users", "/api/admin/roles/{id}"]

    text = _report(tmp_path, inventory)
    assert text.index("Findings Summary") < text.index("Endpoints") < text.index("1. Code Security")
    for expected in ("Routes per protection", "Public state-changing routes", "Sensitive routes",
                     "POST", "/api/notifications", "main.go:16",
                     "GET", "/api/admin/users", "PUT", "/api/admin/roles/{id}", "authenticated",
                     "main.go:23", "main.go:24"):
        assert expected in text
    # Unknown routes are counted and never listed as a route to review.
    assert "startJob" not in text


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
