from pathlib import Path

import yaml

from scripts.validate_rules import validate_manifest


ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules" / "opengrep-rules"


def test_rule_manifest_is_valid_and_covers_exactly_19_rules():
    result = validate_manifest(ROOT / "rules" / "manifest.yaml", RULES)
    assert result.rule_count == 19
    assert result.errors == []


def test_new_rules_have_required_security_metadata():
    expected = {
        "scp.python.injection.subprocess-shell",
        "scp.python.deserialization.unsafe-yaml-load",
    }
    found = {}
    for path in (RULES / "python").glob("*.yaml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for rule in doc.get("rules", []):
            if rule.get("id") in expected:
                found[rule["id"]] = rule
    assert set(found) == expected
    for rule in found.values():
        metadata = rule["metadata"]
        assert metadata["license"] == "MIT"
        assert metadata["confidence"] in {"HIGH", "MEDIUM"}
        assert metadata["cwe"]
        assert metadata["owasp"]
        assert metadata["references"]
        assert metadata["remediation"]


def test_new_rules_match_vulnerable_but_not_safe_fixtures():
    import json
    import subprocess

    config = RULES / "python" / "additional-security.yaml"
    fixtures = ROOT / "tests" / "rules" / "python"
    vulnerable = fixtures / "vulnerable.py"
    safe = fixtures / "safe.py"
    proc = subprocess.run(
        [
            str(ROOT / ".venv" / "bin" / "semgrep"),
            "scan", "--quiet", "--json", "--no-git-ignore",
            "--config", str(config), str(vulnerable), str(safe),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode in (0, 1), proc.stderr
    results = json.loads(proc.stdout)["results"]
    paths = [item["path"] for item in results]
    assert any(path.endswith("vulnerable.py") for path in paths)
    assert not any(path.endswith("safe.py") for path in paths)
    assert {item["check_id"].split(".")[-1] for item in results} >= {
        "subprocess-shell",
        "unsafe-yaml-load",
    }
