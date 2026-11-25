"""First page layout, Top risks and Fix First grouping (PLAN D6 and D8, task N05)."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import sdt_impact  # noqa: E402
import sdt_priority  # noqa: E402
import sdt_to_docx  # noqa: E402

W_NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def _docx_xml(path: Path) -> ET.Element:
    with zipfile.ZipFile(path) as zf:
        return ET.fromstring(zf.read("word/document.xml"))


def _elem_text(elem: ET.Element) -> str:
    return "".join(elem.itertext())


def _table_rows(tbl: ET.Element) -> list[list[str]]:
    return [
        ["".join(tc.itertext()).strip() for tc in tr.findall("w:tc", W_NS)]
        for tr in tbl.findall("w:tr", W_NS)
    ]


def _docx_sections(path: Path) -> tuple[list[str], list[list[list[str]]], str]:
    """Return (paragraphs, tables, full_text) from word/document.xml."""
    root = _docx_xml(path)
    body = root.find("w:body", W_NS)
    assert body is not None
    paras = [_elem_text(p) for p in body.findall("w:p", W_NS)]
    tables = [_table_rows(t) for t in body.findall("w:tbl", W_NS)]
    return paras, tables, _elem_text(body)


def build_reference_scenario(tmp_path: Path, kev: tuple[str, ...] = ()) -> tuple[sdt_to_docx.Report, Path]:
    """Synthetic example-service matching the PLAN reference scenario (Spring Boot 2.4.4 + npm)."""
    src_root = tmp_path / "example-service"
    src_root.mkdir(parents=True, exist_ok=True)
    (src_root / "pom.xml").write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.4.4</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>example-service</artifactId>
  <version>1.0.0</version>
</project>
""",
        encoding="utf-8",
    )
    (src_root / "package-lock.json").write_text('{"name":"example-service","lockfileVersion":3}\n', encoding="utf-8")

    # 6 state-changing BOLA routes on credential/contact fields in UserController.java
    # plus 2 read-only BOLA routes in the same controller.
    bola_routes = [
        (20, 28, "PUT /api/users/{userId}/password", "account-takeover", "high"),
        (32, 40, "PUT /api/users/{userId}/pin", "account-takeover", "high"),
        (44, 52, "PUT /api/users/{userId}/email", "account-takeover", "high"),
        (56, 64, "PUT /api/users/{userId}/phone", "account-takeover", "high"),
        (68, 76, "POST /api/users/{userId}/otp", "account-takeover", "high"),
        (80, 88, "POST /api/users/{userId}/mfa", "account-takeover", "high"),
        (96, 102, "GET /api/users/{userId}/profile", "data-exposure", "medium"),
        (106, 112, "GET /api/users/{userId}/activity", "data-exposure", "medium"),
    ]
    findings: list[dict] = []
    for start, end, ep, imp, sev in bola_routes:
        findings.append({
            "scanner": {"adapter": "endpoints"},
            "category": "sast",
            "rule": {
                "id": "scp.endpoints.bola-unscoped-object-access",
                "name": "Authenticated object route accesses store without caller ownership check",
                "cwe": ["CWE-639"],
            },
            "severity": {"canonical": sev},
            "message": f"{ep} accepts object parameter {{userId}} without checking caller ownership.",
            "location": {"path": "src/main/java/com/app/UserController.java", "startLine": start, "endLine": end},
            "metadata": {"endpoint": ep, "impact": imp},
            "remediation": {
                "guidance": "Derive the caller identity from the verified principal and scope the query to the caller.",
            },
        })

    # 4 of the 6 state-changing handlers also flagged by credential-change-by-request-id 2 lines lower.
    for start, _, ep, _, _ in bola_routes[:4]:
        findings.append({
            "scanner": {"adapter": "opengrep"},
            "category": "sast",
            "rule": {
                "id": "scp.java.authz.credential-change-by-request-id",
                "name": "Credential change for an account named in the URL",
                "cwe": ["CWE-639"],
            },
            "severity": {"canonical": "high"},
            "message": f"Updates credentials for path userId on {ep}.",
            "location": {"path": "src/main/java/com/app/UserController.java", "startLine": start + 2},
            "remediation": {"guidance": "Load the target user from the authenticated principal instead of the request."},
        })

    # 2 over-broad permitAll prefixes + 1 security chain without a default rule in SecurityConfig.java.
    for line, prefix in ((24, "/api/users/**"), (30, "/api/account/**")):
        findings.append({
            "scanner": {"adapter": "opengrep"},
            "category": "sast",
            "rule": {
                "id": "scp.java.authz.permitall-wildcard-prefix",
                "name": "Over-broad permitAll wildcard prefix",
                "cwe": ["CWE-862"],
            },
            "severity": {"canonical": "high"},
            "message": f"permitAll() applied to broad prefix {prefix}.",
            "location": {"path": "src/main/java/com/app/SecurityConfig.java", "startLine": line},
            "remediation": {"guidance": "Restrict permitAll() to exact public routes."},
        })
    findings.append({
        "scanner": {"adapter": "opengrep"},
        "category": "sast",
        "rule": {
            "id": "scp.java.authz.security-chain-without-default",
            "name": "Security chain without a default authorization rule",
            "cwe": ["CWE-862"],
        },
        "severity": {"canonical": "high"},
        "message": "SecurityFilterChain does not finish with anyRequest().authenticated().",
        "location": {"path": "src/main/java/com/app/SecurityConfig.java", "startLine": 42},
        "remediation": {"guidance": "End the SecurityFilterChain with anyRequest().authenticated()."},
    })

    # 2 hard-coded passwords in application-prod.yml (line 12 flagged by two rules).
    for line, key_name in ((12, "spring.datasource.password"), (25, "app.mail.password")):
        findings.append({
            "scanner": {"adapter": "opengrep"},
            "category": "sast",
            "rule": {
                "id": "scp.yaml.spring.prod-literal-password",
                "name": "Hard-coded password in production Spring profile",
                "cwe": ["CWE-798"],
            },
            "severity": {"canonical": "high"},
            "message": f"Literal password set for {key_name}.",
            "location": {"path": "src/main/resources/application-prod.yml", "startLine": line},
            "remediation": {"guidance": "Load production passwords from environment variables or a secret manager."},
        })
    findings.append({
        "scanner": {"adapter": "opengrep"},
        "category": "sast",
        "rule": {
            "id": "scp.common.secrets.prod-literal-secret",
            "name": "Hard-coded secret in production configuration",
            "cwe": ["CWE-798"],
        },
        "severity": {"canonical": "high"},
        "message": "Literal secret committed in production profile.",
        "location": {"path": "src/main/resources/application-prod.yml", "startLine": 12},
        "remediation": {"guidance": "Move the production secret out of YAML and into the secret store."},
    })

    # 1 likely false positive in application-tls.yml.
    findings.append({
        "scanner": {"adapter": "opengrep"},
        "category": "sast",
        "rule": {
            "id": "scp.yaml.spring.keystore-in-repository",
            "name": "Keystore reference in Spring configuration",
            "cwe": ["CWE-798"],
        },
        "severity": {"canonical": "high"},
        "message": "Keystore file referenced in application-tls.yml.",
        "location": {"path": "src/main/resources/application-tls.yml", "startLine": 8},
        "remediation": {"guidance": "Mount TLS keystores at runtime instead of bundling them."},
    })

    # 6 passwords stored in a recoverable form in PasswordService.java.
    for idx in range(6):
        findings.append({
            "scanner": {"adapter": "opengrep"},
            "category": "sast",
            "rule": {
                "id": "scp.java.crypto.recoverable-password",
                "name": "Password stored in a recoverable form",
                "cwe": ["CWE-257"],
            },
            "severity": {"canonical": "high"},
            "message": "Encrypts user password with reversible AES instead of a password hash.",
            "location": {"path": "src/main/java/com/app/PasswordService.java", "startLine": 14 + idx * 12},
            "remediation": {"guidance": "Hash passwords with BCrypt, Argon2 or scrypt instead of reversible encryption."},
        })

    # 16 vulnerable Maven packages managed by Spring Boot (12 Critical, 4 High; includes major jumps -> Migration).
    spring_packages = [
        ("org.springframework:spring-webmvc", "5.3.5", "6.0.15", "CVE-2022-22965", "critical"),
        ("org.springframework:spring-beans", "5.3.5", "6.0.15", "CVE-2022-22965", "critical"),
        ("org.springframework:spring-core", "5.3.5", "6.0.15", "CVE-2023-20861", "critical"),
        ("org.springframework:spring-context", "5.3.5", "6.0.15", "CVE-2023-20863", "critical"),
        ("org.springframework:spring-expression", "5.3.5", "6.0.15", "CVE-2023-20861", "critical"),
        ("org.springframework.security:spring-security-core", "5.4.5", "6.0.8", "CVE-2023-34034", "critical"),
        ("org.springframework.security:spring-security-web", "5.4.5", "6.0.8", "CVE-2023-34034", "critical"),
        ("org.springframework.boot:spring-boot", "2.4.4", "3.0.13", "CVE-2023-20873", "critical"),
        ("org.springframework.boot:spring-boot-autoconfigure", "2.4.4", "3.0.13", "CVE-2023-20873", "critical"),
        ("org.apache.tomcat.embed:tomcat-embed-core", "9.0.44", "10.1.18", "CVE-2023-46589", "critical"),
        ("com.fasterxml.jackson.core:jackson-databind", "2.11.4", "2.15.3", "CVE-2022-42003", "critical"),
        ("org.yaml:snakeyaml", "1.27", "2.0", "CVE-2022-1471", "critical"),
        ("ch.qos.logback:logback-classic", "1.2.3", "1.2.13", "CVE-2023-6378", "high"),
        ("ch.qos.logback:logback-core", "1.2.3", "1.2.13", "CVE-2023-6378", "high"),
        ("org.hibernate:hibernate-core", "5.4.29", "5.6.15", "CVE-2020-25638", "high"),
        ("io.netty:netty-codec-http", "4.1.60", "4.1.104", "CVE-2023-44487", "high"),
    ]
    for pkg, inst, fix, cve, sev in spring_packages:
        findings.append({
            "scanner": {"adapter": "trivy"},
            "category": "sca",
            "rule": {"id": cve},
            "severity": {"canonical": sev},
            "artifact": {"package": pkg, "installedVersion": inst, "fixedVersion": fix, "target": "pom.xml"},
            "reachability": {"state": "reachable"},
        })

    # 5 vulnerable npm packages (same-major fixed versions -> Drop-in).
    npm_packages = [
        ("semver", "7.3.5", "7.5.4", "CVE-2022-25883", "high"),
        ("minimatch", "3.0.4", "3.1.2", "CVE-2022-3517", "high"),
        ("json5", "2.2.0", "2.2.3", "CVE-2022-46175", "high"),
        ("word-wrap", "1.2.3", "1.2.5", "CVE-2023-26115", "medium"),
        ("postcss", "8.4.12", "8.4.31", "CVE-2023-44270", "medium"),
    ]
    for pkg, inst, fix, cve, sev in npm_packages:
        findings.append({
            "scanner": {"adapter": "trivy"},
            "category": "sca",
            "rule": {"id": cve},
            "severity": {"canonical": sev},
            "artifact": {"package": pkg, "installedVersion": inst, "fixedVersion": fix, "target": "package-lock.json"},
            "reachability": {"state": "reachable"},
        })

    found = sdt_to_docx.from_findings({"findings": findings}, src_root)

    # 21 debug-feature hotspots (SonarQube java:S4507, C3 medium -> P4) and
    # 2 hard-coded IPs (SonarQube java:S1313, C4 medium -> P4).
    found["code"].append(sdt_to_docx.Group(
        "java:S4507",
        "Delivering code in production with debug features activated",
        "Security Hotspot",
        "Medium",
        occurrences=[
            sdt_to_docx.Occurrence(
                f"src/main/java/com/app/DebugHelper{idx % 3}.java",
                10 + idx,
                "Make sure this debug feature is deactivated before delivering the code in production.",
                "To review",
                "",
            )
            for idx in range(21)
        ],
    ))
    found["code"].append(sdt_to_docx.Group(
        "java:S1313",
        "Using hardcoded IP addresses is security-sensitive",
        "Security Hotspot",
        "Medium",
        occurrences=[
            sdt_to_docx.Occurrence(
                "src/main/java/com/app/NetworkConfig.java",
                18 + idx * 5,
                "Make sure using this hardcoded IP address is safe here.",
                "To review",
                "",
            )
            for idx in range(2)
        ],
    ))

    # Attach likely_false_positive review to the application-tls.yml finding (with unique AI text
    # so tests can verify no AI prose ever leaks onto page 1).
    for g in found["code"]:
        if g.rule.endswith("scp.yaml.spring.keystore-in-repository"):
            g.occurrences[0].ai = {
                "verdict": "likely_false_positive",
                "confidence": "high",
                "reason": "SENTINEL_AI_REASON_TLS_PLACEHOLDER",
                "check": "SENTINEL_AI_CHECK_TLS_PROFILE",
                "suggested_fix": "SENTINEL_AI_FIX_TLS",
            }

    report = sdt_to_docx.Report(
        "example-service",
        "example/example-service",
        "branch main",
        "",
        "abc1234",
        "SDT",
        found["code"],
        found["secret"],
        found["dependency"],
        found["config"],
        sdt_to_docx.date(2026, 11, 24),
        src_root=src_root,
        kev=kev,
    )
    return report, src_root


def test_reference_scenario_first_page_and_fix_first(tmp_path):
    report, src_root = build_reference_scenario(tmp_path)
    out = tmp_path / "example-service.docx"
    sdt_to_docx.write_docx(report, src_root, out)
    sdt_to_docx.prioritize(report, src_root)

    paras, tables, full_text = _docx_sections(out)
    first_page_end = full_text.index("Fix First", full_text.index("Contents") + 50)
    first_page = full_text[:first_page_end]

    # 1. Summary of actions at the top of Executive Summary, and P4 counts for debug/IP hotspots.
    exec_idx = paras.index("Executive Summary")
    assert paras[exec_idx + 1].startswith("Summary of actions: code and secrets, ")
    assert "dependencies, 2 upgrade actions (1 Migration, 1 Drop-in)." in paras[exec_idx + 1]
    assert "P4 23" in first_page and "P3 " not in first_page

    # 2. Top risks: <= 5 lines, starts with Account takeover, no AI text on page 1.
    risks = sdt_to_docx.top_risks(report)
    assert 1 <= len(risks) <= 5
    assert risks[0].startswith("Account takeover:")
    assert "6 routes in UserController.java" in risks[0]
    assert "Top risks" in first_page
    for risk in risks:
        assert risk in first_page
    for sentinel in ("SENTINEL_AI_REASON_TLS_PLACEHOLDER", "SENTINEL_AI_CHECK_TLS_PROFILE", "SENTINEL_AI_FIX_TLS"):
        assert sentinel not in first_page

    # 3. Fix First code & secret actions: <= 10 rows, proper columns (no Severity), proper priorities.
    rows = sdt_to_docx.fix_first(report)
    assert len(rows) <= 10
    p1_rows = [r for r in rows if r[0] == "P1"]
    p2_rows = [r for r in rows if r[0] == "P2"]
    assert p1_rows[0][1] == "Account takeover"
    # All 6 state-changing routes named once; 4 credential-change duplicates merged into that single row.
    ato_rows = [r for r in rows if r[1] == "Account takeover"]
    assert len(ato_rows) == 1
    assert "6 routes:" in ato_rows[0][2]
    for ep in (
        "PUT /api/users/{userId}/password",
        "PUT /api/users/{userId}/pin",
        "PUT /api/users/{userId}/email",
        "PUT /api/users/{userId}/phone",
        "POST /api/users/{userId}/otp",
        "POST /api/users/{userId}/mfa",
    ):
        assert ato_rows[0][2].count(ep) == 1
    assert "Credential change for an account named in the URL" in ato_rows[0][2]

    # Auth bypass and production credential actions are at P1; read BOLA and recoverable passwords are at P2.
    assert any(r[1] == "Authentication bypass" for r in p1_rows)
    assert any(r[1] == "Credential exposure" and "application-prod.yml" in r[3] for r in p1_rows)
    assert any(r[1] == "Data exposure" and "2 routes:" in r[2] for r in p2_rows)
    assert any(r[1] == "Weak credential storage" and "6 findings" in r[2] for r in p2_rows)

    # Debug hotspots (P4) and hard-coded IPs (P4) stay out of Fix First.
    assert all(r[1] not in ("Defence in depth", "Hygiene") for r in rows)

    # Fix First table headers match PLAN D8 (no Severity column) and intro describes impact classes.
    fix_table = next(t for t in tables if t and t[0] == ["No.", "Priority", "Impact", "Action and scope", "Where", "Why"])
    assert len(fix_table) == 1 + len(rows)
    assert "Severity" not in fix_table[0]
    fix_heading_idx = paras.index("Fix First", paras.index("Fix First") + 1)
    fix_intro = paras[fix_heading_idx + 1]
    assert "fix before the next deploy" in fix_intro and "fix in this release" in fix_intro
    assert "impact class (C1 Direct compromise to C4 Hygiene)" in fix_intro
    assert "Priority starts from the severity" not in fix_intro

    # Dependency upgrades table: 2 rows, both P2, Spring Boot Migration and npm Drop-in.
    dep_rows = sdt_to_docx.fix_first_upgrades(report)
    assert len(dep_rows) == 2
    assert dep_rows[0][0] == "P2" and "Spring Boot (currently 2.4.4)" in dep_rows[0][1] and dep_rows[0][3] == "Migration"
    assert dep_rows[1][0] == "P2" and "Update npm lockfile" in dep_rows[1][1] and dep_rows[1][3] == "Drop-in"


def test_reference_scenario_with_kev_promotes_spring_boot_to_p1(tmp_path):
    report, src_root = build_reference_scenario(tmp_path, kev=("CVE-2022-22965",))
    out = tmp_path / "example-service-kev.docx"
    sdt_to_docx.write_docx(report, src_root, out)
    sdt_to_docx.prioritize(report, src_root)

    dep_rows = sdt_to_docx.fix_first_upgrades(report)
    assert len(dep_rows) == 2
    assert dep_rows[0][0] == "P1" and "Spring Boot (currently 2.4.4)" in dep_rows[0][1]
    assert "CVE-2022-22965" in dep_rows[0][4]
    assert dep_rows[1][0] == "P2" and "Update npm lockfile" in dep_rows[1][1]

    risks = sdt_to_docx.top_risks(report)
    assert len(risks) <= 5
    assert risks[0].startswith("Account takeover:")
    assert "Outdated Spring Boot: one upgrade fixes 12 Critical and 4 High packages." in risks


def test_d6_grouping_splits_by_file_and_priority_and_truncates_many_routes():
    bola = sdt_to_docx.Group(
        "endpoints:scp.endpoints.bola-unscoped-object-access",
        "Unscoped object access",
        "Finding",
        "High",
        fixes=["Verify record ownership."],
        occurrences=[
            sdt_to_docx.Occurrence(
                "src/UserController.java",
                10 + i * 5,
                f"PUT /api/users/{{id}}/pin-{i}",
                "Not reviewed",
                "",
                impact="account-takeover",
                endpoint=f"PUT /api/users/{{id}}/pin-{i}",
            )
            for i in range(10)
        ] + [
            sdt_to_docx.Occurrence(
                "src/AdminController.java",
                10,
                "PUT /api/admins/{id}/password",
                "Not reviewed",
                "",
                impact="account-takeover",
                endpoint="PUT /api/admins/{id}/password",
            ),
        ],
    )
    # Same rule in same file at two different priorities (P1 via confirmed review, P2 unreviewed).
    sqli_medium = sdt_to_docx.Group(
        "java:S2077",
        "Formatting SQL queries",
        "Security Hotspot",
        "High",
        fixes=["Use parameterized queries."],
        occurrences=[
            sdt_to_docx.Occurrence(
                "src/Repo.java", 15, "sql1", "To review", "",
                ai={"verdict": "likely_true_positive", "confidence": "high", "suggested_fix": "Bind params on line 15."},
            ),
            sdt_to_docx.Occurrence("src/Repo.java", 30, "sql2", "To review", ""),
        ],
    )
    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", [bola, sqli_medium], [], [], [],
                                sdt_to_docx.date(2026, 11, 24))
    sdt_to_docx.prioritize(report)

    rows = sdt_to_docx.fix_first(report)
    # 1 grouped action for 10 routes in UserController + 1 for AdminController + 1 P1 + 1 P2 in Repo.java = 4 rows.
    assert len(rows) == 4
    user_row = next(r for r in rows if "UserController.java" in r[3])
    assert "10 routes:" in user_row[2] and "and 2 more" in user_row[2]
    assert any("src/AdminController.java:10" == r[3] for r in rows)
    repo_rows = [r for r in rows if "Repo.java" in r[3]]
    assert {r[0] for r in repo_rows} == {"P1", "P2"}
    p1_repo = next(r for r in repo_rows if r[0] == "P1")
    assert "Bind params on line 15." in p1_repo[2]


def test_fix_first_sort_order_priority_class_label_size():
    # P1 C1 Injection (size 1) vs P1 C1 Account takeover (size 1) vs P1 C1 Authentication bypass (size 2 and size 1)
    # vs P2 C1 Credential exposure (size 1) vs P2 C2 Data exposure (size 3).
    sqli = sdt_to_docx.Group("java:S3649", "SQLi", "Vulnerability", "High",
                             occurrences=[sdt_to_docx.Occurrence("src/A.java", 10, "sqli", "Open", "")])
    ato = sdt_to_docx.Group("scp.java.authz.credential-change-by-request-id", "Cred change", "Vulnerability", "High",
                            occurrences=[sdt_to_docx.Occurrence("src/B.java", 10, "ato", "Open", "")])
    bypass_small = sdt_to_docx.Group("scp.java.authz.security-chain-without-default", "No default", "Vulnerability", "High",
                                     occurrences=[sdt_to_docx.Occurrence("src/C.java", 10, "chain", "Open", "")])
    bypass_large = sdt_to_docx.Group("scp.java.authz.permitall-wildcard-prefix", "Broad permitAll", "Vulnerability", "High",
                                     occurrences=[
                                         sdt_to_docx.Occurrence("src/D.java", 10, "p1", "Open", ""),
                                         sdt_to_docx.Occurrence("src/D.java", 20, "p2", "Open", ""),
                                     ])
    p2_c1 = sdt_to_docx.Group("scp.yaml.spring.keystore-in-repository", "Keystore", "Vulnerability", "High",
                              occurrences=[sdt_to_docx.Occurrence("src/tls.yml", 5, "ks", "Open", "")])
    p2_c2 = sdt_to_docx.Group("scp.endpoints.bola-unscoped-object-access", "Read BOLA", "Finding", "Medium",
                              occurrences=[
                                  sdt_to_docx.Occurrence("src/E.java", 10 + i, f"GET /api/items/{{id}}/{i}",
                                                         "Not reviewed", "", impact="data-exposure")
                                  for i in range(3)
                              ])

    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT",
                                [p2_c2, p2_c1, sqli, bypass_small, bypass_large, ato], [], [], [],
                                sdt_to_docx.date(2026, 11, 24))
    sdt_to_docx.prioritize(report)
    actions = sdt_to_docx.fix_first_actions(report)
    assert [(a.level, a.klass, a.impact, a.size) for a in actions] == [
        ("P1", "C1", "Account takeover", 1),
        ("P1", "C1", "Authentication bypass", 2),
        ("P1", "C1", "Authentication bypass", 1),
        ("P1", "C1", "Injection", 1),
        ("P2", "C1", "Credential exposure", 1),
        ("P2", "C2", "Data exposure", 3),
    ]


def test_top_risk_templates_cover_all_plan_d1_labels_and_secret_and_dependency_lines():
    for labels in sdt_impact.LABELS_BY_CLASS.values():
        for label in labels:
            assert label in sdt_to_docx.TOP_RISK_TEMPLATES, f"missing template for {label}"

    # Verify Secret leak and P2 dependency line appear when fewer than 5 code labels exist.
    secret = sdt_to_docx.SecretRow("private-key", "deploy/id_rsa", 1, "abc123", "Current code", "High")
    dep = sdt_to_docx.DependencyRow("semver", "7.3.5", "package-lock.json",
                                    {"CVE-2022-25883": "7.5.4"}, {"CVE-2022-25883": "High"}, "Yes")
    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", [], [secret], [dep], [],
                                sdt_to_docx.date(2026, 11, 24))
    sdt_to_docx.prioritize(report)
    risks = sdt_to_docx.top_risks(report)
    assert risks == [
        "Secret leak: leaked credentials were found in the repository or its git history (1 secret in id_rsa).",
        "Outdated package-lock.json: one upgrade fixes 1 High package.",
    ]


def test_fix_first_cap_counts_actions_not_findings(tmp_path):
    # 42 separate files with 2 findings each -> 42 actions -> 40 rows + "2 more actions".
    group = sdt_to_docx.Group(
        "java:S3649",
        "SQL injection",
        "Vulnerability",
        "High",
        occurrences=[
            sdt_to_docx.Occurrence(f"src/File{i:02d}.java", line, "sqli", "Open", "")
            for i in range(42)
            for line in (10, 20)
        ],
    )
    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", [group], [], [], [],
                                sdt_to_docx.date(2026, 11, 24))
    out = tmp_path / "cap.docx"
    sdt_to_docx.write_docx(report, None, out)
    _, tables, text = _docx_sections(out)
    fix_table = next(t for t in tables if t and t[0] == ["No.", "Priority", "Impact", "Action and scope", "Where", "Why"])
    assert len(fix_table) == 41  # header + 40 rows
    assert "2 more actions at P1 or P2 follow in the sections below" in text


def test_merge_backfills_endpoint_from_findings_and_sonar_extracts_endpoint():
    sonar_key = "external_sdt-endpoints:scp.endpoints.bola-unscoped-object-access"
    sonar_occ = sdt_to_docx.Occurrence(
        "src/UserController.java", 20, "PUT /api/users/{id}/password accepts object parameter", "Open", "",
        endpoint=sdt_to_docx._extract_endpoint(sonar_key, "PUT /api/users/{id}/password accepts object parameter"),
    )
    assert sonar_occ.endpoint == "PUT /api/users/{id}/password"

    sonar_no_ep = sdt_to_docx.Occurrence("src/UserController.java", 20, "Unscoped store access", "Open", "")
    sdt_with_ep = sdt_to_docx.Occurrence("src/UserController.java", 20, "Unscoped store access", "Not reviewed", "",
                                         end_line=28, impact="account-takeover",
                                         endpoint="PUT /api/users/{id}/password")
    sonar = {
        "code": [sdt_to_docx.Group(sonar_key, "BOLA", "Finding", "High", occurrences=[sonar_no_ep])],
        "secret": [], "dependency": [], "config": [],
    }
    sdt = {
        "code": [sdt_to_docx.Group("endpoints:scp.endpoints.bola-unscoped-object-access", "BOLA", "Finding",
                                   "High", occurrences=[sdt_with_ep])],
        "secret": [], "dependency": [], "config": [],
    }
    merged = sdt_to_docx.merge(sonar, sdt)
    occ = merged["code"][0].occurrences[0]
    assert occ.endpoint == "PUT /api/users/{id}/password"
    assert occ.impact == "account-takeover"
    assert occ.end_line == 28


def _five_label_groups() -> list:
    """Open code findings with five different impact labels at P1 or P2, one file each."""
    def group(rule, name, path, **occ):
        return sdt_to_docx.Group(rule, name, "Vulnerability", "High",
                                 occurrences=[sdt_to_docx.Occurrence(path, 10, name, "Open", "", **occ)])
    return [
        group("scp.java.authz.credential-change-by-request-id", "Cred change", "src/A.java"),
        group("scp.java.authz.security-chain-without-default", "No default", "src/B.java"),
        group("java:S3649", "SQLi", "src/C.java"),
        group("scp.endpoints.bola-unscoped-object-access", "Read BOLA", "src/D.java", impact="data-exposure"),
        group("scp.java.crypto.recoverable-password", "Recoverable", "src/E.java"),
    ]


def _dep(package: str, manifest: str, severity: str, n: int = 1) -> list:
    return [sdt_to_docx.DependencyRow(f"{package}{i}", "1.0.0", manifest, {f"CVE-2020-{1000 + i}": "1.0.1"},
                                      {f"CVE-2020-{1000 + i}": severity}, "Yes") for i in range(n)]


def test_top_risks_keeps_dependency_line_and_drops_least_urgent_code_label():
    deps = _dep("lib", "requirements.txt", "High")
    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", _five_label_groups(), [], deps, [],
                                sdt_to_docx.date(2026, 11, 24))
    sdt_to_docx.prioritize(report)
    risks = sdt_to_docx.top_risks(report)
    assert len(risks) == 5
    assert risks[-1].startswith("Outdated requirements.txt: one upgrade fixes 1 High package")
    labels = [r.split(":")[0] for r in risks[:-1]]
    assert labels == ["Account takeover", "Authentication bypass", "Injection", "Data exposure"]


def test_top_risks_puts_a_known_exploited_upgrade_before_p2_lines():
    deps = _dep("lib", "requirements.txt", "High")
    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", _five_label_groups(), [], deps, [],
                                sdt_to_docx.date(2026, 11, 24), kev={"CVE-2020-1000"})
    sdt_to_docx.prioritize(report)
    risks = sdt_to_docx.top_risks(report)
    assert [r.split(":")[0] for r in risks] == [
        "Account takeover", "Authentication bypass", "Injection", "Outdated requirements.txt", "Data exposure"]


def test_top_risks_names_the_upgrade_that_fixes_the_most_severe_packages():
    lock = _dep("npm", "package-lock.json", "Critical", 5) + _dep("npmh", "package-lock.json", "High", 40)
    gradle = _dep("jvm", "build.gradle", "Critical", 11) + _dep("jvmh", "build.gradle", "High", 19)
    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", [], [], lock + gradle, [],
                                sdt_to_docx.date(2026, 11, 24))
    sdt_to_docx.prioritize(report)
    assert sdt_to_docx.top_risks(report) == ["Outdated build.gradle: one upgrade fixes 11 Critical and 19 High packages."]


def test_fix_first_action_uses_rule_help_from_findings_json():
    def finding(rule_id, help_text):
        return {"rule": {"id": rule_id, "name": "Unscoped object access", "help": help_text},
                "scanner": {"adapter": "endpoints"}, "category": "sast", "severity": {"canonical": "high"},
                "message": "PUT /api/users/{id}/pin accepts object parameter {id}",
                "location": {"path": "src/UserController.java", "startLine": 20},
                "metadata": {"impact": "account-takeover", "endpoint": "PUT /api/users/{id}/pin"}}
    help_text = ("Derive the caller identity from the verified token and filter the query. "
                 "Return 404 for records the caller does not own.")
    found = sdt_to_docx.from_findings({"findings": [finding("scp.endpoints.bola-unscoped-object-access", help_text)]})
    assert found["code"][0].fixes == ["Derive the caller identity from the verified token and filter the query.",
                                      "Return 404 for records the caller does not own."]
    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", found["code"], [], [], [],
                                sdt_to_docx.date(2026, 11, 24))
    sdt_to_docx.prioritize(report)
    assert sdt_to_docx.fix_first_actions(report)[0].action_scope.startswith("Derive the caller identity")

    bare = sdt_to_docx.from_findings({"findings": [finding("scp.endpoints.bola-unscoped-object-access", "")]})
    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", bare["code"], [], [], [],
                                sdt_to_docx.date(2026, 11, 24))
    sdt_to_docx.prioritize(report)
    assert sdt_to_docx.fix_first_actions(report)[0].action_scope.startswith("Fix, or mark False positive with a reason")


def test_help_fixes_keeps_whole_sentences_within_the_limit():
    long = "A" * 250 + ". " + "B" * 100 + "."
    assert sdt_to_docx._help_fixes(long) == ["A" * 250 + "."]
    assert sdt_to_docx._help_fixes("") == []


def test_merge_takes_sdt_rule_help_when_sonarqube_has_no_description():
    sonar_group = sdt_to_docx.Group("external_sdt-endpoints:scp.endpoints.bola-unscoped-object-access", "BOLA",
                                    "Vulnerability", "Medium",
                                    occurrences=[sdt_to_docx.Occurrence("src/U.java", 20, "m", "Open", "")])
    described = sdt_to_docx.Group("java:S3649", "SQLi", "Vulnerability", "High", fixes=["Use bound parameters."],
                                  occurrences=[sdt_to_docx.Occurrence("src/R.java", 5, "m", "Open", "")])
    sdt_group = sdt_to_docx.Group("endpoints:scp.endpoints.bola-unscoped-object-access", "BOLA", "Finding", "Medium",
                                  fixes=["Scope the query to the caller."])
    other = sdt_to_docx.Group("opengrep:java:S3649", "SQLi", "Finding", "High", fixes=["Something else."])
    sonar = {"code": [sonar_group, described], "secret": [], "dependency": [], "config": []}
    sdt = {"code": [sdt_group, other], "secret": [], "dependency": [], "config": []}
    merged = sdt_to_docx.merge(sonar, sdt)
    by_rule = {g.rule: g.fixes for g in merged["code"]}
    assert by_rule[sonar_group.rule] == ["Scope the query to the caller."]
    assert by_rule["java:S3649"] == ["Use bound parameters."]


def test_report_survives_a_withheld_value_equal_to_a_section_name(tmp_path):
    """A repository whose code holds `("secret", "dependency", "config")` (SDT scanning itself) made the
    redaction rename the resolved findings' "dependency" key, and the report crashed with KeyError."""
    src = tmp_path / "src"
    (src / "tools").mkdir(parents=True)
    (src / "tools" / "report.py").write_text('for key in ("secret", "dependency", "config"):\n    pass\n')
    group = sdt_to_docx.Group("python:S1", "A rule", "Vulnerability", "High",
                              occurrences=[sdt_to_docx.Occurrence("tools/report.py", 1, "m", "Open", "")])
    decided = sdt_to_docx.Group("python:S2", "Decided", "Vulnerability", "High",
                                occurrences=[sdt_to_docx.Occurrence("tools/report.py", 2, "m", "Safe", "")])
    resolved = {"code": [decided], "secret": [], "dependency": [], "config": []}
    report = sdt_to_docx.Report("app", "ws/app", "main", "", "abc", "SDT", [group], [], [], [],
                                sdt_to_docx.date(2026, 11, 25), resolved=resolved)
    out = tmp_path / "r.docx"
    sdt_to_docx.write_docx(report, src, out)
    assert out.stat().st_size > 0


def test_report_xml_stays_valid_when_a_withheld_value_is_part_of_a_tag_name(tmp_path):
    """`password = "app"` in scanned code withholds "app"; scrubbing it out of the raw XML turned
    <w:clrSchemeMapping> into an invalid tag and Word refused the report."""
    import xml.parsers.expat
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (src / "app" / "Client.java").write_text('String password = "app";\nString token = "s3cret-Value-9";\n')
    group = sdt_to_docx.Group("java:S2068", "Hard-coded credential", "Vulnerability", "High",
                              occurrences=[sdt_to_docx.Occurrence("app/Client.java", 1, "m", "Open", ""),
                                           sdt_to_docx.Occurrence("app/Client.java", 2, "m", "Open", "")])
    report = sdt_to_docx.Report("app-service", "ws/app-service", "main", "", "abc", "SDT", [group], [], [], [],
                                sdt_to_docx.date(2026, 11, 25))
    out = tmp_path / "r.docx"
    sdt_to_docx.write_docx(report, src, out)
    with zipfile.ZipFile(out) as z:
        for name in z.namelist():
            if name.endswith((".xml", ".rels")):
                xml.parsers.expat.ParserCreate().Parse(z.read(name), True)  # raises on a broken part
        text = z.read("word/document.xml").decode()
        assert "s3cret-Value-9" not in text and "SAST Report" in z.read("word/header1.xml").decode()
        assert "app-service" in text  # the project name is not cut by the withheld "app"
