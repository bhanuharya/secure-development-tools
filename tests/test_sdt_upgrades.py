"""Dependency upgrade action grouping, KEV cap and DOCX rendering (PLAN D7, N04)."""
from __future__ import annotations

import json
import sys
import zipfile
from datetime import date
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import sdt_priority as prio  # noqa: E402
import sdt_to_docx as docx  # noqa: E402
import sdt_upgrades as upgrades  # noqa: E402


SPRING_BOOT_27_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>example-service</artifactId>
  <version>1.0.0</version>
</project>
"""


def _docx_text(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        root = ElementTree.fromstring(archive.read("word/document.xml"))
    return "".join(root.itertext())


def _reference_rows() -> list[docx.DependencyRow]:
    """Reference scenario: 8 Spring-managed Maven packages, 1 unmanaged Maven package, 4 npm lock packages (13 total)."""
    return [
        # 8 Spring-managed packages in pom.xml
        docx.DependencyRow("org.springframework:spring-webmvc", "5.3.31", "pom.xml",
                           {"CVE-2026-1001": "6.1.14"}, {"CVE-2026-1001": "Critical"}, "Yes"),
        docx.DependencyRow("org.springframework:spring-core", "5.3.31", "pom.xml",
                           {"CVE-2026-1002": "6.1.14"}, {"CVE-2026-1002": "High"}, "Yes"),
        docx.DependencyRow("org.springframework.security:spring-security-core", "5.7.11", "pom.xml",
                           {"CVE-2026-1003": "6.2.4"}, {"CVE-2026-1003": "Critical"}, "Yes"),
        docx.DependencyRow("org.apache.tomcat.embed:tomcat-embed-core", "9.0.85", "pom.xml",
                           {"CVE-2026-1004": "10.1.25"}, {"CVE-2026-1004": "High"}, "Yes"),
        docx.DependencyRow("com.fasterxml.jackson.core:jackson-databind", "2.13.5", "pom.xml",
                           {"CVE-2026-1005": "2.16.2"}, {"CVE-2026-1005": "High"}, "Yes"),
        docx.DependencyRow("io.netty:netty-handler", "4.1.104", "pom.xml",
                           {"CVE-2026-1006": "4.1.112"}, {"CVE-2026-1006": "Medium"}, "No"),
        docx.DependencyRow("ch.qos.logback:logback-classic", "1.2.13", "pom.xml",
                           {"CVE-2026-1007": "1.4.14"}, {"CVE-2026-1007": "High"}, "No"),
        docx.DependencyRow("org.yaml:snakeyaml", "1.30", "pom.xml",
                           {"CVE-2026-1008": "2.2"}, {"CVE-2026-1008": "High"}, "No"),
        # 1 unmanaged Maven package in pom.xml
        docx.DependencyRow("org.apache.commons:commons-text", "1.9", "pom.xml",
                           {"CVE-2026-2001": "1.10.0"}, {"CVE-2026-2001": "Critical"}, "Yes"),
        # 4 npm packages in frontend/package-lock.json
        docx.DependencyRow("lodash", "4.17.19", "frontend/package-lock.json",
                           {"CVE-2026-3001": "4.17.21"}, {"CVE-2026-3001": "Critical"}, "Yes"),
        docx.DependencyRow("axios", "1.6.0", "frontend/package-lock.json",
                           {"CVE-2026-3002": "1.7.4"}, {"CVE-2026-3002": "High"}, "Yes"),
        docx.DependencyRow("tar", "6.1.0", "frontend/package-lock.json",
                           {"CVE-2026-3003": "6.2.1"}, {"CVE-2026-3003": "High"}, "Yes"),
        docx.DependencyRow("semver", "7.5.0", "frontend/package-lock.json",
                           {"CVE-2026-3004": "7.5.4"}, {"CVE-2026-3004": "Medium"}, "No"),
    ]


def _write_reference_manifests(root: Path) -> None:
    (root / "pom.xml").write_text(SPRING_BOOT_27_POM, encoding="utf-8")
    (root / "frontend").mkdir(parents=True, exist_ok=True)
    (root / "frontend" / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")


def test_reference_scenario_groups_and_kev_rules(tmp_path):
    src = tmp_path / "repo"
    src.mkdir()
    _write_reference_manifests(src)

    # 1. Without KEV: 13 packages collapse into 3 actions, every action <= P2.
    actions = upgrades.group_upgrades(_reference_rows(), src)
    assert len(actions) == 3
    by_title = {a.title: a for a in actions}
    spring = by_title["Upgrade Spring Boot (currently 2.7.18)"]
    unmanaged = by_title["Upgrade org.apache.commons:commons-text (1.9 -> 1.10.0)"]
    npm = by_title["Update npm lockfile (frontend/package-lock.json)"]

    assert len(spring.packages) == 8 and spring.effort == "Migration"
    assert spring.counts == {"Critical": 2, "High": 5, "Medium": 1}
    assert spring.targets["org.springframework:spring-webmvc"] == "6.1.14"
    assert spring.priority.level == "P2"
    assert "capped at P2: no known-exploited advisory" in spring.priority.why

    assert len(unmanaged.packages) == 1 and unmanaged.effort == "Drop-in"
    assert unmanaged.priority.level == "P2"
    assert "capped at P2: no known-exploited advisory" in unmanaged.priority.why

    assert len(npm.packages) == 4 and npm.effort == "Drop-in"
    assert npm.counts == {"Critical": 1, "High": 2, "Medium": 1}
    assert npm.priority.level == "P2"
    assert "capped at P2: no known-exploited advisory" in npm.priority.why
    assert all(a.priority.rank >= 1 for a in actions)

    # 2. With a KEV fixture listing an imported Spring CVE -> Spring action becomes P1; others stay P2.
    kev_imported = tmp_path / "kev-imported.json"
    kev_imported.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-1001"}]}), encoding="utf-8")
    kev_set = upgrades.load_kev(kev_imported)
    actions_kev = upgrades.group_upgrades(_reference_rows(), src, kev=kev_set)
    by_title_kev = {a.title: a for a in actions_kev}
    spring_kev = by_title_kev["Upgrade Spring Boot (currently 2.7.18)"]
    assert spring_kev.priority.level == "P1"
    assert spring_kev.kev == ("CVE-2026-1001",)
    assert "on the known-exploited list: CVE-2026-1001" in spring_kev.priority.why
    assert by_title_kev["Upgrade org.apache.commons:commons-text (1.9 -> 1.10.0)"].priority.level == "P2"
    assert by_title_kev["Update npm lockfile (frontend/package-lock.json)"].priority.level == "P2"

    # 3. With a KEV fixture listing ONLY an unreachable package's CVE (snakeyaml reachable == "No") -> stays P2.
    kev_unreach = tmp_path / "kev-unreachable.json"
    kev_unreach.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-1008"}]}), encoding="utf-8")
    actions_unreach = upgrades.group_upgrades(_reference_rows(), src, kev=upgrades.load_kev(kev_unreach))
    spring_unreach = {a.title: a for a in actions_unreach}["Upgrade Spring Boot (currently 2.7.18)"]
    assert spring_unreach.priority.level == "P2"
    assert spring_unreach.kev == ("CVE-2026-1008",)
    assert "capped at P2: no known-exploited advisory" in spring_unreach.priority.why


def test_missing_pom_falls_back_to_per_package_while_lockfiles_and_other_manifests_still_group(tmp_path):
    empty_src = tmp_path / "empty"
    empty_src.mkdir()
    # Missing pom.xml falls back to 1 action per Maven package (9), while lockfile still groups (1) -> 10 actions.
    rows = _reference_rows()
    ctx = prio.Context("unknown")
    actions = upgrades.group_upgrades(rows, empty_src, ctx=ctx)
    maven_actions = [a for a in actions if a.manifest == "pom.xml"]
    npm_actions = [a for a in actions if a.manifest == "frontend/package-lock.json"]
    assert len(maven_actions) == 9
    assert len(npm_actions) == 1 and len(npm_actions[0].packages) == 4
    for action in maven_actions:
        (row,) = action.packages
        assert action.priority == prio.dependency(row.severity, row.reachable, row.manifest, ctx)


def test_jhipster_bom_groups_spring_managed_including_thymeleaf_micrometer_hazelcast(tmp_path):
    src = tmp_path / "jhipster-svc"
    src.mkdir()
    (src / "pom.xml").write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>billing-service</artifactId>
  <version>1.0.0</version>
  <properties>
    <jhipster-dependencies.version>7.0.1</jhipster-dependencies.version>
    <spring-boot.version>2.4.4</spring-boot.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>tech.jhipster</groupId>
        <artifactId>jhipster-dependencies</artifactId>
        <version>${jhipster-dependencies.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
""", encoding="utf-8")

    rows = [
        docx.DependencyRow("org.springframework:spring-webmvc", "5.3.5", "pom.xml",
                           {"CVE-2026-5001": "6.1.14"}, {"CVE-2026-5001": "Critical"}, "Yes"),
        docx.DependencyRow("org.thymeleaf:thymeleaf", "3.0.12.RELEASE", "pom.xml",
                           {"CVE-2026-5002": "3.0.15.RELEASE"}, {"CVE-2026-5002": "High"}, "Yes"),
        docx.DependencyRow("io.micrometer:micrometer-core", "1.6.5", "pom.xml",
                           {"CVE-2026-5003": "1.12.5"}, {"CVE-2026-5003": "Medium"}, "Yes"),
        docx.DependencyRow("com.hazelcast:hazelcast", "4.1.2", "pom.xml",
                           {"CVE-2026-5004": "5.3.6"}, {"CVE-2026-5004": "High"}, "Yes"),
        docx.DependencyRow("tech.jhipster:jhipster-framework", "7.0.1", "pom.xml",
                           {"CVE-2026-5005": "8.0.0"}, {"CVE-2026-5005": "Medium"}, "Yes"),
        # Unmanaged third-party Maven package stays its own action
        docx.DependencyRow("org.apache.commons:commons-text", "1.9", "pom.xml",
                           {"CVE-2026-5006": "1.10.0"}, {"CVE-2026-5006": "Critical"}, "Yes"),
    ]
    actions = upgrades.group_upgrades(rows, src)
    assert len(actions) == 2
    by_title = {a.title: a for a in actions}
    jh = by_title["Upgrade JHipster (currently 7.0.1; Spring Boot 2.4.4)"]
    assert len(jh.packages) == 5
    assert jh.effort == "Migration"
    assert "Upgrade org.apache.commons:commons-text (1.9 -> 1.10.0)" in by_title

    # Legacy io.github.jhipster BOM without spring-boot.version property omits the Spring Boot clause.
    (src / "pom.xml").write_text("""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>io.github.jhipster</groupId>
        <artifactId>jhipster-dependencies</artifactId>
        <version>6.10.5</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
""", encoding="utf-8")
    same_major = [
        docx.DependencyRow("org.thymeleaf:thymeleaf", "3.0.12.RELEASE", "pom.xml",
                           {"CVE-2026-5002": "3.0.15.RELEASE"}, {"CVE-2026-5002": "High"}, "Yes"),
    ]
    legacy = upgrades.group_upgrades(same_major, src)
    assert len(legacy) == 1
    assert legacy[0].title == "Upgrade JHipster (currently 6.10.5)"
    assert legacy[0].effort == "Drop-in"


def test_effort_depends_only_on_major_version_jump_even_on_spring_boot_2(tmp_path):
    src = tmp_path / "sb2-patch"
    src.mkdir()
    (src / "pom.xml").write_text(SPRING_BOOT_27_POM, encoding="utf-8")
    patch_rows = [
        docx.DependencyRow("org.springframework:spring-webmvc", "5.3.31", "pom.xml",
                           {"CVE-2026-6001": "5.3.39"}, {"CVE-2026-6001": "High"}, "Yes"),
        docx.DependencyRow("org.apache.tomcat.embed:tomcat-embed-core", "9.0.85", "pom.xml",
                           {"CVE-2026-6002": "9.0.90"}, {"CVE-2026-6002": "High"}, "Yes"),
    ]
    actions = upgrades.group_upgrades(patch_rows, src)
    assert len(actions) == 1 and actions[0].effort == "Drop-in"


def test_kev_respects_internal_service_and_package_never_ranks_above_action(tmp_path):
    src = tmp_path / "repo"
    src.mkdir()
    _write_reference_manifests(src)
    kev = {"CVE-2026-1001"}

    # Internal service with normal criticality: KEV action is P2 (not P1).
    internal_actions = upgrades.group_upgrades(_reference_rows(), src, kev=kev, ctx=prio.Context("internal"))
    spring_internal = {a.title: a for a in internal_actions}["Upgrade Spring Boot (currently 2.7.18)"]
    assert spring_internal.priority.level == "P2"
    assert "on the known-exploited list: CVE-2026-1001" in spring_internal.priority.why
    assert "internal service ↓" in spring_internal.priority.why

    # Internal service with high criticality: KEV action is P1.
    high_actions = upgrades.group_upgrades(_reference_rows(), src, kev=kev, ctx=prio.Context("internal", "high"))
    spring_high = {a.title: a for a in high_actions}["Upgrade Spring Boot (currently 2.7.18)"]
    assert spring_high.priority.level == "P1"

    # Package rows in a report never rank above their action (no P1 package under a P2 action).
    report = docx.Report("example", "ws/example", "branch main", "", "abc", "SDT",
                         [], [], _reference_rows(), [], date(2026, 11, 24), src_root=src)
    docx.prioritize(report, src)
    for action in report.upgrades:
        for pkg in action.packages:
            assert pkg.priority.rank >= action.priority.rank
    assert all(r.priority.rank >= 1 for r in report.dependencies)  # no KEV -> no P1 package rows


def test_other_ecosystems_group_by_manifest_without_files_and_java_archives_stay_per_package():
    rows = [
        docx.DependencyRow("golang.org/x/net", "0.17.0", "go.mod",
                           {"CVE-2026-7001": "0.23.0"}, {"CVE-2026-7001": "High"}, "Yes"),
        docx.DependencyRow("golang.org/x/crypto", "0.14.0", "go.mod",
                           {"CVE-2026-7002": "0.21.0"}, {"CVE-2026-7002": "High"}, "Yes"),
        docx.DependencyRow("urllib3", "1.26.15", "requirements.txt",
                           {"CVE-2026-7003": "2.2.2"}, {"CVE-2026-7003": "High"}, "Yes"),
        docx.DependencyRow("requests", "2.28.0", "requirements.txt",
                           {"CVE-2026-7004": "2.32.2"}, {"CVE-2026-7004": "Medium"}, "Yes"),
        docx.DependencyRow("com.example:sdk", "1.0.0", "build.gradle",
                           {"CVE-2026-7005": "1.0.1"}, {"CVE-2026-7005": "High"}, "Yes"),
        docx.DependencyRow("com.example:core", "1.0.0", "build.gradle",
                           {"CVE-2026-7006": "1.0.2"}, {"CVE-2026-7006": "Medium"}, "Yes"),
        docx.DependencyRow("http", "0.13.5", "pubspec.yaml",
                           {"CVE-2026-7007": "0.13.6"}, {"CVE-2026-7007": "Medium"}, "Yes"),
        docx.DependencyRow("dio", "5.3.0", "pubspec.yaml",
                           {"CVE-2026-7008": "5.4.0"}, {"CVE-2026-7008": "High"}, "Yes"),
        # Java archives stay one action per package
        docx.DependencyRow("com.example:a", "1.0", "dist/app.jar",
                           {"CVE-2026-7009": "1.1"}, {"CVE-2026-7009": "High"}, "Yes"),
        docx.DependencyRow("com.example:b", "1.0", "dist/app.jar",
                           {"CVE-2026-7010": "1.1"}, {"CVE-2026-7010": "High"}, "Yes"),
        docx.DependencyRow("com.example:c", "1.0", "deploy/svc.war",
                           {"CVE-2026-7011": "1.1"}, {"CVE-2026-7011": "Medium"}, "Yes"),
        docx.DependencyRow("com.example:d", "1.0", "deploy/suite.ear",
                           {"CVE-2026-7012": "1.1"}, {"CVE-2026-7012": "Medium"}, "Yes"),
    ]
    actions = upgrades.group_upgrades(rows, src_root=None)
    titles = {a.title: a for a in actions}
    assert "Update 2 packages in go.mod" in titles and titles["Update 2 packages in go.mod"].effort == "Drop-in"
    assert "Update 2 packages in requirements.txt" in titles and titles["Update 2 packages in requirements.txt"].effort == "Migration"
    assert "Update 2 packages in build.gradle" in titles
    assert "Update 2 packages in pubspec.yaml" in titles
    archive_actions = [a for a in actions if a.manifest.endswith((".jar", ".war", ".ear"))]
    assert len(archive_actions) == 4 and all(len(a.packages) == 1 for a in archive_actions)
    assert docx.upgrade_to is upgrades.upgrade_to


def test_maven_bom_import_property_resolution_and_unparsable_pom_fallback(tmp_path):
    src = tmp_path / "bom-repo"
    src.mkdir()
    (src / "pom.xml").write_text("""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <spring-boot.version>3.2.4</spring-boot.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>${spring-boot.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
""", encoding="utf-8")
    rows = [
        docx.DependencyRow("org.springframework:spring-web", "6.1.5", "pom.xml",
                           {"CVE-2026-4001": "6.1.6"}, {"CVE-2026-4001": "High"}, "Yes"),
        docx.DependencyRow("com.fasterxml.jackson.core:jackson-databind", "2.15.3", "pom.xml",
                           {"CVE-2026-4002": "2.15.4"}, {"CVE-2026-4002": "High"}, "Yes"),
    ]
    actions = upgrades.group_upgrades(rows, src)
    assert len(actions) == 1
    assert actions[0].title == "Upgrade Spring Boot (currently 3.2.4)"
    assert actions[0].effort == "Drop-in"

    # Unparsable pom.xml must not raise; falls back to one action per package.
    (src / "pom.xml").write_text("<project><broken", encoding="utf-8")
    fallback = upgrades.group_upgrades(rows, src)
    assert len(fallback) == 2


def test_load_kev_warns_on_missing_file_without_raising(tmp_path):
    warnings: list[str] = []
    got = upgrades.load_kev(tmp_path / "does-not-exist.json", warn=warnings.append)
    assert got == set()
    assert len(warnings) == 1 and "not found" in warnings[0]


def test_report_renders_dependency_upgrades_in_fix_first_and_section_3(tmp_path):
    src = tmp_path / "repo"
    src.mkdir()
    _write_reference_manifests(src)
    # Include a P3 action (Low/unreachable unmanaged package) to verify Fix First omits it while section 3 shows it.
    rows = _reference_rows() + [
        docx.DependencyRow("com.example:unused-util", "1.0.0", "pom.xml",
                           {"CVE-2026-9999": "1.0.1"}, {"CVE-2026-9999": "Medium"}, "No"),
    ]
    report = docx.Report("example", "ws/example", "branch main", "", "abc", "SDT",
                         [], [], rows, [], date(2026, 11, 24), src_root=src)
    out = tmp_path / "upgrades.docx"
    docx.write_docx(report, src, out)
    text = _docx_text(out)

    # First page Priority counts actions (3 P2 + 1 P4 = 4 actions, NOT 14 packages).
    assert "PriorityP2 3, P4 1" in text
    # Findings Summary keeps package counts and explicitly says "packages" in its label.
    assert "Dependencies (packages) & Configuration (Trivy)" in text
    # Fix First has the second table "Dependency upgrades" with open P1/P2 actions only.
    fix_idx = text.index("Fix First", text.index("Contents") + 50)
    sec1_idx = text.index("1. Code Security", fix_idx)
    fix_text = text[fix_idx:sec1_idx]
    assert "Dependency upgrades" in fix_text
    assert "Upgrade Spring Boot (currently 2.7.18)" in fix_text
    assert "Update npm lockfile (frontend/package-lock.json)" in fix_text
    assert "org.apache.commons:commons-text" in fix_text
    assert "Migration" in fix_text and "Drop-in" in fix_text
    assert "com.example:unused-util" not in fix_text  # P4 stays out of Fix First

    # Section 3 starts with all Upgrade Actions (including P4), then Vulnerable Packages.
    sec3_idx = text.index("3. Dependencies & Configuration (Trivy)", sec1_idx)
    sec3_text = text[sec3_idx:]
    assert sec3_text.index("3.1 Upgrade Actions") < sec3_text.index("3.2 Vulnerable Packages")
    assert "4 upgrade actions covering 14 vulnerable packages" in sec3_text
    assert "com.example:unused-util" in sec3_text


def test_cli_kev_option_and_env_var_handle_valid_and_missing_catalog(tmp_path, monkeypatch, capsys):
    src = tmp_path / "repo"
    src.mkdir()
    _write_reference_manifests(src)
    findings = {"findings": [{
        "scanner": {"adapter": "trivy-fs"}, "category": "dependency-vulnerability",
        "rule": {"id": "CVE-2026-1001"}, "severity": {"canonical": "critical"},
        "message": "Spring vulnerability",
        "artifact": {"package": "org.springframework:spring-webmvc", "installedVersion": "5.3.31",
                     "fixedVersion": "6.1.14", "target": "pom.xml"},
        "reachability": {"state": "reachable"},
    }]}
    fjson = tmp_path / "findings.json"
    fjson.write_text(json.dumps(findings), encoding="utf-8")
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-1001"}]}), encoding="utf-8")

    # --kev elevates imported Spring CVE to P1
    out1 = tmp_path / "with-kev.docx"
    monkeypatch.setattr(sys, "argv", [
        "sdt_to_docx.py", "--findings", str(fjson), "--src-root", str(src),
        "--kev", str(kev), "--out", str(out1),
    ])
    assert docx.main() == 0
    assert "PriorityP1 1" in _docx_text(out1)

    # SDT_KEV_FILE env var works when --kev is omitted
    out2 = tmp_path / "env-kev.docx"
    monkeypatch.setenv("SDT_KEV_FILE", str(kev))
    monkeypatch.setattr(sys, "argv", [
        "sdt_to_docx.py", "--findings", str(fjson), "--src-root", str(src), "--out", str(out2),
    ])
    assert docx.main() == 0
    assert "PriorityP1 1" in _docx_text(out2)

    # Missing KEV file warns, exits 0, and caps action at P2
    out3 = tmp_path / "missing-kev.docx"
    monkeypatch.delenv("SDT_KEV_FILE", raising=False)
    monkeypatch.setattr(sys, "argv", [
        "sdt_to_docx.py", "--findings", str(fjson), "--src-root", str(src),
        "--kev", str(tmp_path / "missing.json"), "--out", str(out3),
    ])
    assert docx.main() == 0
    assert "not found" in capsys.readouterr().err
    assert "PriorityP2 1" in _docx_text(out3)


def test_reports_sh_passes_kev_only_when_sdt_kev_file_is_set(tmp_path):
    import os
    import subprocess

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_file = tmp_path / "calls.log"
    fake_py = bin_dir / "python3"
    fake_py.write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> {log_file}\n", encoding="utf-8")
    fake_py.chmod(0o755)

    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out"
    (out / "sdt").mkdir(parents=True)
    (out / "sdt" / "findings.json").write_text('{"findings": []}\n', encoding="utf-8")
    (out / "sdt" / "run-manifest.json").write_text('{"tasks": []}\n', encoding="utf-8")

    base_env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "SRC": str(src),
        "OUT": str(out),
        "REPO_SLUG": "example-service",
        "SDT_HOME": str(ROOT),
    }

    # Without SDT_KEV_FILE: --kev must NOT be passed.
    res_unset = subprocess.run(
        ["bash", str(ROOT / "integrations/jenkins/resources/sdt/reports.sh")],
        env=base_env, capture_output=True, text=True, check=False,
    )
    assert res_unset.returncode == 0, res_unset.stderr
    unset_calls = [line for line in log_file.read_text().splitlines() if "sdt_to_docx.py" in line]
    assert len(unset_calls) == 1 and "--kev" not in unset_calls[0]

    # With SDT_KEV_FILE set: --kev <path> MUST be passed.
    log_file.unlink()
    kev_path = str(tmp_path / "kev.json")
    res_set = subprocess.run(
        ["bash", str(ROOT / "integrations/jenkins/resources/sdt/reports.sh")],
        env={**base_env, "SDT_KEV_FILE": kev_path}, capture_output=True, text=True, check=False,
    )
    assert res_set.returncode == 0, res_set.stderr
    set_calls = [line for line in log_file.read_text().splitlines() if "sdt_to_docx.py" in line]
    assert len(set_calls) == 1 and f"--kev {kev_path}" in set_calls[0]

