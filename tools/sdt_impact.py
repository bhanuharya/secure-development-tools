#!/usr/bin/env python3
"""Impact classes for code findings (PLAN D1 and D2).

Maps a code rule key (or its CWE ids as a fallback) to an impact class (C1 to
C4), a plain-English impact label for developers, a rule precision ("high" or
"medium"), and whether exploiting the weakness requires an attacker to reach the
service (`needs_reach`).

Lookup order:
  1. `RULES`: every first-party `scp.*` rule in `rules/opengrep-rules/` and
     every `scp.endpoints.*` rule in `internal/endpoints/`.
  2. `VENDOR_RULES`: commonly reported vendored OpenGrep rules (`vendor.*`).
  3. `SONAR_RULES`: SonarQube security rules across Java, Kotlin, JavaScript,
     TypeScript, Python, Go, Dart, Docker and shared web/XML/secrets engines.
  4. `CWE`: fallback table when the rule key itself is not mapped.

Standard library only.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

CLASS_CEILING: dict[str, int] = {"C1": 0, "C2": 1, "C3": 2, "C4": 3}

LABELS_BY_CLASS: dict[str, tuple[str, ...]] = {
    "C1": (
        "Account takeover",
        "Authentication bypass",
        "Credential exposure",
        "Injection",
    ),
    "C2": (
        "Data exposure",
        "Logic abuse",
        "Request forgery",
        "Cross-site scripting",
        "Weak credential storage",
    ),
    "C3": ("Defence in depth",),
    "C4": ("Hygiene",),
}

NO_REACH_LABELS: frozenset[str] = frozenset({
    "Credential exposure",
    "Weak credential storage",
})

# Tuple format for rule tables: (klass, label, precision, needs_reach).
RuleEntry = tuple[str, str, str, bool]


@dataclass(frozen=True)
class Impact:
    klass: str
    label: str
    precision: str
    needs_reach: bool
    source: str  # "rule" | "sonar" | "cwe"


# ----------------------------------------------------------------------- first-party rules
# Every scp.* rule in rules/opengrep-rules/**/*.yaml and every scp.endpoints.*
# rule in internal/endpoints/*.go must appear here (enforced by tests).
RULES: dict[str, RuleEntry] = {
    # Endpoint inventory and access-control engine (internal/endpoints/*.go)
    "scp.endpoints.bola-unscoped-object-access": (
        "C2", "Data exposure", "high", True,
    ),  # default entry; refined per finding (read vs state-changing/credential) in N03
    "scp.endpoints.invariant-violated": (
        "C1", "Authentication bypass", "high", True,
    ),  # violates a repository-declared route security contract
    "scp.endpoints.protection-downgraded": ("C1", "Authentication bypass", "high", True),
    "scp.endpoints.sensitive-route-public": ("C1", "Authentication bypass", "high", True),
    "scp.endpoints.sensitive-route-without-role": (
        "C1", "Authentication bypass", "medium", True,
    ),  # sensitive route allows any logged-in user where peer routes check roles; medium so review confirms
    "scp.endpoints.spring-matcher-depth-mismatch": ("C1", "Authentication bypass", "high", True),
    "scp.endpoints.state-change-on-get-or-any": (
        "C2", "Request forgery", "medium", False,
    ),  # GET mutation breaks CSRF defences (rides on an internal user's browser); ANY bypasses method matchers
    "scp.endpoints.unprotected-among-protected": (
        "C1", "Authentication bypass", "medium", True,
    ),  # majority-convention heuristic can hit an intentional public route; medium so review confirms

    # Common deployment and secrets
    "scp.common.deploy.dev-server-start": (
        "C2", "Data exposure", "high", True,
    ),  # dev servers in deployment manifests expose source files and debug routes without auth
    "scp.common.deploy.start-script-dev-server": ("C3", "Defence in depth", "medium", True),
    "scp.common.secrets.aws-access-key-id": ("C1", "Credential exposure", "high", False),
    "scp.common.secrets.credentials-in-url": ("C1", "Credential exposure", "medium", False),
    "scp.common.secrets.known-default-secret": ("C1", "Credential exposure", "high", False),
    "scp.common.secrets.placeholder-default-literal": ("C1", "Credential exposure", "high", False),
    "scp.common.secrets.private-key": ("C1", "Credential exposure", "high", False),
    "scp.common.secrets.prod-literal-secret": (
        "C1", "Credential exposure", "high", False,
    ),  # literal secret inside a production config profile; high so prod credentials rank P1 directly
    "scp.common.secrets.public-build-variable": ("C1", "Credential exposure", "medium", False),

    # Dart and Flutter
    "scp.dart.crypto.aes-ecb": ("C3", "Defence in depth", "high", False),
    "scp.dart.crypto.recoverable-password": ("C2", "Weak credential storage", "high", False),
    "scp.dart.crypto.weak-md5": ("C3", "Defence in depth", "high", False),
    "scp.dart.crypto.weak-sha1": ("C3", "Defence in depth", "high", False),
    "scp.dart.crypto.zero-key": ("C1", "Credential exposure", "high", False),
    "scp.dart.injection.command": ("C1", "Injection", "medium", True),
    "scp.dart.injection.sql": ("C1", "Injection", "medium", True),
    "scp.dart.random.insecure": ("C3", "Defence in depth", "medium", False),
    "scp.dart.secrets.hardcoded-secret": ("C1", "Credential exposure", "medium", False),
    "scp.dart.tls.disable-certificate-validation": (
        "C2", "Data exposure", "high", False,
    ),  # completely disables TLS peer verification (active MITM traffic capture), stronger than weak cipher/TLS hardening
    "scp.dart.webview.javascript-unrestricted": ("C3", "Defence in depth", "medium", True),
    "scp.dart.webview.untrusted-script": ("C2", "Cross-site scripting", "medium", True),
    "scp.flutter.android.cleartext-traffic": ("C3", "Defence in depth", "high", False),
    "scp.flutter.android.custom-scheme-link": ("C3", "Defence in depth", "medium", True),
    "scp.flutter.android.debuggable": ("C3", "Defence in depth", "high", False),
    "scp.flutter.android.exported-without-permission": (
        "C2", "Logic abuse", "medium", False,
    ),  # local IPC component accessible to other apps on the device
    "scp.flutter.android.fileprovider-broad-path": (
        "C2", "Data exposure", "medium", False,
    ),  # FileProvider root exposure readable by local apps on the device
    "scp.flutter.auth.biometric-allows-fallback": ("C3", "Defence in depth", "medium", False),
    "scp.flutter.crypto.static-iv": ("C3", "Defence in depth", "high", False),
    "scp.flutter.deeplink.unvalidated-handler": ("C2", "Logic abuse", "medium", True),
    "scp.flutter.ios.ats-arbitrary-loads": ("C3", "Defence in depth", "high", False),
    "scp.flutter.logging.sensitive-data": ("C2", "Data exposure", "medium", False),
    "scp.flutter.network.cleartext-http": ("C3", "Defence in depth", "medium", False),
    "scp.flutter.secrets.hardcoded-api-key": ("C1", "Credential exposure", "high", False),
    "scp.flutter.storage.shared-preferences-secret": ("C2", "Weak credential storage", "high", False),
    "scp.flutter.webview.javascript-channel": ("C2", "Cross-site scripting", "medium", True),

    # Go
    "scp.go.authz.route-without-auth-middleware": ("C1", "Authentication bypass", "medium", True),
    "scp.go.crypto.recoverable-password": ("C2", "Weak credential storage", "high", False),
    "scp.go.injection.command": ("C1", "Injection", "high", True),
    "scp.go.logging.secret-in-log": (
        "C2", "Data exposure", "medium", False,
    ),  # CWE-532 log-call rules can match benign names; stays P3 until confirmed, P2 when real, keeping P1 noise-free
    "scp.go.logic.check-then-act-balance-race": ("C2", "Logic abuse", "medium", True),
    "scp.go.logic.mass-assignment-db-model": ("C2", "Logic abuse", "medium", True),
    "scp.go.logic.non-constant-time-token-compare": ("C3", "Defence in depth", "medium", False),
    "scp.go.logic.trust-spoofable-identity-header": ("C1", "Authentication bypass", "medium", True),
    "scp.go.logic.unbounded-pagination-limit": ("C3", "Defence in depth", "medium", True),
    "scp.go.logic.weak-prng-otp-or-token": ("C2", "Logic abuse", "high", False),
    "scp.go.path-traversal.request-controlled-path": (
        "C1", "Injection", "medium", True,
    ),  # arbitrary file read, write or delete via request-controlled path
    "scp.go.secrets.hardcoded-secret": ("C1", "Credential exposure", "medium", False),

    # HCL / Terraform
    "scp.hcl.aws.sg-open-ingress": (
        "C3", "Defence in depth", "medium", True,
    ),  # 0.0.0.0/0 may be intentional on a public load balancer
    "scp.hcl.gcp.firewall-open-internal-port": (
        "C1", "Authentication bypass", "high", True,
    ),  # opens internal registry, database or broker ports directly to 0.0.0.0/0

    # Java
    "scp.java.authz.client-supplied-authorities": ("C2", "Logic abuse", "medium", True),
    "scp.java.authz.commented-out-rule": ("C1", "Authentication bypass", "medium", True),
    "scp.java.authz.credential-change-by-request-id": ("C1", "Account takeover", "high", True),
    "scp.java.authz.noop-security-check": ("C1", "Authentication bypass", "medium", True),
    "scp.java.authz.permitall-credential-check": ("C1", "Authentication bypass", "medium", True),
    "scp.java.authz.permitall-internal-path": ("C1", "Authentication bypass", "high", True),
    "scp.java.authz.permitall-wildcard-prefix": (
        "C1", "Authentication bypass", "high", True,
    ),  # high so over-broad permitAll prefixes rank P1 without relying on AI review
    "scp.java.authz.security-chain-scoped-to-list": ("C1", "Authentication bypass", "high", True),
    "scp.java.authz.security-chain-without-default": (
        "C1", "Authentication bypass", "high", True,
    ),  # high so missing default authorization ranks P1 without relying on AI review
    "scp.java.boundary.request-data-in-session": ("C2", "Logic abuse", "medium", True),
    "scp.java.cors.any-origin-with-credentials": (
        "C2", "Data exposure", "high", True,
    ),  # wildcard origin combined with allowCredentials exposes authenticated responses cross-origin
    "scp.java.crypto.recoverable-password": ("C2", "Weak credential storage", "high", False),
    "scp.java.crypto.weak-md5": ("C3", "Defence in depth", "high", False),
    "scp.java.debug.test-endpoint": ("C3", "Defence in depth", "medium", True),
    "scp.java.injection.command": ("C1", "Injection", "high", True),
    "scp.java.injection.sql-string-from-request": ("C1", "Injection", "high", True),
    "scp.java.logging.secret-in-log-call": ("C2", "Data exposure", "medium", False),
    "scp.java.logging.tostring-prints-secret": ("C2", "Data exposure", "medium", False),
    "scp.java.logic.check-then-act-balance-race": ("C2", "Logic abuse", "medium", True),
    "scp.java.logic.float-for-currency": ("C2", "Logic abuse", "medium", False),
    "scp.java.logic.mass-assignment-beanutils": ("C2", "Logic abuse", "medium", True),
    "scp.java.logic.trust-spoofable-identity-header": ("C1", "Authentication bypass", "medium", True),
    "scp.java.logic.unbounded-page-size": ("C3", "Defence in depth", "medium", True),
    "scp.java.logic.weak-prng-otp-or-token": ("C2", "Logic abuse", "high", False),
    "scp.java.oauth.admin-client-credentials": ("C1", "Authentication bypass", "high", True),
    "scp.java.path.request-path-to-file-operation": (
        "C1", "Injection", "high", True,
    ),  # tainted request path reaching file read, write or delete
    "scp.java.search.user-controlled-query-string": ("C2", "Data exposure", "medium", True),
    "scp.java.secrets.hardcoded-secret": ("C1", "Credential exposure", "medium", False),
    "scp.java.ssrf.request-controlled-url": ("C2", "Request forgery", "medium", True),
    "scp.java.websocket.any-origin": (
        "C2", "Request forgery", "medium", False,
    ),  # cross-site WebSocket hijacking rides on an internal user's browser like CSRF
    "scp.java.websocket.handler-without-interceptor": (
        "C2", "Logic abuse", "medium", True,
    ),  # low-confidence rule because auth often lives in SecurityFilterChain; stays P3 unless review confirms

    # JavaScript and TypeScript
    "scp.javascript.authz.credential-change-by-request-id": ("C1", "Account takeover", "high", True),
    "scp.javascript.authz.route-without-auth-middleware": ("C1", "Authentication bypass", "medium", True),
    "scp.javascript.crypto.recoverable-password": ("C2", "Weak credential storage", "high", False),
    "scp.javascript.injection.eval": ("C1", "Injection", "high", True),
    "scp.javascript.logging.secret-in-console": ("C2", "Data exposure", "medium", False),
    "scp.javascript.logging.secret-in-log": ("C2", "Data exposure", "medium", False),
    "scp.javascript.logic.mass-assignment-req-body": ("C2", "Logic abuse", "medium", True),
    "scp.javascript.logic.non-constant-time-token-compare": ("C3", "Defence in depth", "medium", False),
    "scp.javascript.logic.trust-spoofable-identity-header": ("C1", "Authentication bypass", "medium", True),
    "scp.javascript.logic.unbounded-pagination-limit": ("C3", "Defence in depth", "medium", True),
    "scp.javascript.logic.weak-prng-otp-or-token": ("C2", "Logic abuse", "high", False),
    "scp.javascript.secrets.env-fallback-literal": ("C1", "Credential exposure", "high", False),
    "scp.javascript.secrets.hardcoded-secret": ("C1", "Credential exposure", "medium", False),
    "scp.javascript.secrets.literal-basic-credential": ("C1", "Credential exposure", "high", False),
    "scp.javascript.ssrf.request-controlled-url": ("C2", "Request forgery", "medium", True),
    "scp.javascript.xss.innerHTML": ("C2", "Cross-site scripting", "medium", True),
    "scp.typescript.injection.eval": ("C1", "Injection", "high", True),

    # Kotlin
    "scp.kotlin.crypto.recoverable-password": ("C2", "Weak credential storage", "high", False),
    "scp.kotlin.injection.command": ("C1", "Injection", "high", True),
    "scp.kotlin.logging.secret-in-log": ("C2", "Data exposure", "medium", False),
    "scp.kotlin.logic.mass-assignment-beanutils": ("C2", "Logic abuse", "medium", True),
    "scp.kotlin.logic.trust-spoofable-identity-header": ("C1", "Authentication bypass", "medium", True),
    "scp.kotlin.logic.weak-prng-otp-or-token": ("C2", "Logic abuse", "high", False),
    "scp.kotlin.secrets.hardcoded-secret": ("C1", "Credential exposure", "medium", False),

    # Python
    "scp.python.authz.credential-change-by-request-id": ("C1", "Account takeover", "high", True),
    "scp.python.crypto.recoverable-password": ("C2", "Weak credential storage", "high", False),
    "scp.python.crypto.weak-md5": ("C3", "Defence in depth", "high", False),
    "scp.python.deserialization.pickle": ("C1", "Injection", "high", True),
    "scp.python.deserialization.unsafe-yaml-load": ("C1", "Injection", "high", True),
    "scp.python.exec.eval": ("C1", "Injection", "high", True),
    "scp.python.injection.command": ("C1", "Injection", "high", True),
    "scp.python.injection.subprocess-shell": ("C1", "Injection", "high", True),
    "scp.python.logging.secret-in-log": ("C2", "Data exposure", "medium", False),
    "scp.python.logic.mass-assignment-from-request": ("C2", "Logic abuse", "medium", True),
    "scp.python.logic.non-constant-time-token-compare": ("C3", "Defence in depth", "medium", False),
    "scp.python.logic.trust-spoofable-identity-header": ("C1", "Authentication bypass", "medium", True),
    "scp.python.logic.unbounded-pagination-limit": ("C3", "Defence in depth", "medium", True),
    "scp.python.logic.weak-prng-otp-or-token": ("C2", "Logic abuse", "high", False),
    "scp.python.secrets.env-fallback-literal": ("C1", "Credential exposure", "high", False),
    "scp.python.secrets.hardcoded-secret": ("C1", "Credential exposure", "medium", False),

    # YAML, Spring config, gateways and infrastructure
    "scp.generic.nginx.sensitive-location-proxied": ("C1", "Authentication bypass", "high", True),
    "scp.yaml.ci.unpinned-action": ("C3", "Defence in depth", "high", False),
    "scp.yaml.consul.acl-disabled": ("C1", "Authentication bypass", "high", True),
    "scp.yaml.consul.api-on-all-interfaces": ("C3", "Defence in depth", "medium", True),
    "scp.yaml.gateway.sensitive-path-routed": ("C1", "Authentication bypass", "high", True),
    "scp.yaml.k8s.internal-service-ingress": ("C1", "Authentication bypass", "high", True),
    "scp.yaml.k8s.internal-service-public-lb": ("C1", "Authentication bypass", "high", True),
    "scp.yaml.kong.catch-all-route": ("C3", "Defence in depth", "medium", True),
    "scp.yaml.kong.sensitive-path-routed": ("C1", "Authentication bypass", "high", True),
    "scp.yaml.spring.actuator-exposure-env": (
        "C1", "Authentication bypass", "high", True,
    ),  # exposes env/heapdump actuator endpoints without auth over HTTP
    "scp.yaml.spring.actuator-sensitive-endpoints": (
        "C1", "Authentication bypass", "high", True,
    ),  # exposes sensitive actuator endpoints (env, heapdump, mappings) over HTTP
    "scp.yaml.spring.cors-any-origin-with-credentials": ("C2", "Data exposure", "high", True),
    "scp.yaml.spring.gateway-placeholder-access-policy": ("C1", "Authentication bypass", "high", True),
    "scp.yaml.spring.gateway-routes-every-service": ("C3", "Defence in depth", "medium", True),
    "scp.yaml.spring.keystore-in-repository": ("C1", "Credential exposure", "medium", False),
    "scp.yaml.spring.known-default-secret": ("C1", "Credential exposure", "high", False),
    "scp.yaml.spring.prod-debug-logging": ("C3", "Defence in depth", "high", False),
    "scp.yaml.spring.prod-keystore-default-password": ("C1", "Credential exposure", "high", False),
    "scp.yaml.spring.prod-literal-password": (
        "C1", "Credential exposure", "high", False,
    ),  # literal password in a production config profile; high so prod credentials rank P1 directly
    "scp.yaml.spring.prod-literal-secret": (
        "C1", "Credential exposure", "high", False,
    ),  # literal secret in a production config profile
    "scp.yaml.spring.service-url-embedded-credentials": (
        "C3", "Defence in depth", "high", False,
    ),  # interpolates an env variable into a URL (risk of leaking in logs, not a hard-coded secret)
    "scp.yaml.spring.service-url-literal-credentials": ("C1", "Credential exposure", "high", False),
    "scp.yaml.zuul.all-services-routed": ("C3", "Defence in depth", "medium", True),
}


# ----------------------------------------------------------------------- vendored OpenGrep rules
# Commonly reported vendored rules (exact ids from rules/opengrep-rules/vendor/titles.yaml).
VENDOR_RULES: dict[str, RuleEntry] = {
    # Go
    "vendor.semgrep.go.jwt-go.security.audit.jwt-go-parse-unverified": ("C1", "Authentication bypass", "medium", True),
    "vendor.semgrep.go.jwt-go.security.hardcoded-jwt-key": ("C1", "Credential exposure", "high", False),
    "vendor.semgrep.go.jwt-go.security.jwt-go-none-algorithm": ("C1", "Authentication bypass", "high", True),
    "vendor.semgrep.go.lang.security.audit.crypto.avoid-ssh-insecure-ignore-host-key": ("C2", "Data exposure", "high", False),
    "vendor.semgrep.go.lang.security.audit.crypto.math-random-used": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.go.lang.security.audit.crypto.missing-ssl-minversion": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.go.lang.security.audit.crypto.ssl-v3-is-insecure": ("C3", "Defence in depth", "high", False),
    "vendor.semgrep.go.lang.security.audit.crypto.tls-with-insecure-cipher": ("C3", "Defence in depth", "high", False),
    "vendor.semgrep.go.lang.security.audit.crypto.use-of-md5": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.go.lang.security.audit.crypto.use-of-sha1": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.go.lang.security.audit.dangerous-exec-cmd": ("C1", "Injection", "medium", True),
    "vendor.semgrep.go.lang.security.audit.dangerous-exec-command": ("C1", "Injection", "medium", True),
    "vendor.semgrep.go.lang.security.audit.database.string-formatted-query": ("C1", "Injection", "medium", True),
    "vendor.semgrep.go.lang.security.audit.md5-used-as-password": ("C2", "Weak credential storage", "high", False),
    "vendor.semgrep.go.lang.security.audit.net.cookie-missing-httponly": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.go.lang.security.audit.net.cookie-missing-secure": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.go.lang.security.audit.net.pprof-debug-exposure": ("C3", "Defence in depth", "medium", True),
    "vendor.semgrep.go.lang.security.audit.sqli.gosql-sqli": ("C1", "Injection", "medium", True),
    "vendor.semgrep.go.lang.security.audit.sqli.pg-sqli": ("C1", "Injection", "medium", True),
    "vendor.semgrep.go.lang.security.audit.sqli.pgx-sqli": ("C1", "Injection", "medium", True),
    "vendor.semgrep.go.lang.security.audit.xxe.parsing-external-entities-enabled": ("C1", "Injection", "high", True),
    "vendor.semgrep.go.lang.security.injection.open-redirect": ("C2", "Logic abuse", "medium", True),
    "vendor.semgrep.go.lang.security.injection.raw-html-format": ("C2", "Cross-site scripting", "medium", True),
    "vendor.semgrep.go.lang.security.injection.tainted-sql-string": ("C1", "Injection", "high", True),
    "vendor.semgrep.go.lang.security.path-traversal-inside-zip-extraction": ("C1", "Injection", "medium", True),

    # Java
    "vendor.semgrep.java.lang.security.audit.command-injection-formatted-runtime-call": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.command-injection-process-builder": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.cookie-missing-httponly": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.java.lang.security.audit.cookie-missing-secure-flag": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.java.lang.security.audit.crypto.ecb-cipher": ("C3", "Defence in depth", "high", False),
    "vendor.semgrep.java.lang.security.audit.crypto.ssl.insecure-hostname-verifier": ("C2", "Data exposure", "high", False),
    "vendor.semgrep.java.lang.security.audit.crypto.ssl.insecure-trust-manager": ("C2", "Data exposure", "high", False),
    "vendor.semgrep.java.lang.security.audit.crypto.use-of-aes-ecb": ("C3", "Defence in depth", "high", False),
    "vendor.semgrep.java.lang.security.audit.crypto.use-of-md5": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.java.lang.security.audit.crypto.use-of-sha1": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.java.lang.security.audit.crypto.weak-random": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.java.lang.security.audit.formatted-sql-string": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.jdbc-sql-formatted-string": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.md5-used-as-password": ("C2", "Weak credential storage", "high", False),
    "vendor.semgrep.java.lang.security.audit.object-deserialization": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.permissive-cors": ("C3", "Defence in depth", "medium", True),
    "vendor.semgrep.java.lang.security.audit.sqli.hibernate-sqli": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.sqli.jdbc-sqli": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.sqli.jpa-sqli": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.sqli.tainted-sql-from-http-request": ("C1", "Injection", "high", True),
    "vendor.semgrep.java.lang.security.audit.unvalidated-redirect": ("C2", "Logic abuse", "medium", True),
    "vendor.semgrep.java.lang.security.audit.weak-ssl-context": ("C3", "Defence in depth", "high", False),
    "vendor.semgrep.java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-false": ("C1", "Injection", "high", True),
    "vendor.semgrep.java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.xxe.saxparserfactory-disallow-doctype-decl-missing": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled": ("C1", "Injection", "medium", True),
    "vendor.semgrep.java.lang.security.httpservlet-path-traversal": ("C1", "Injection", "high", True),
    "vendor.semgrep.java.lang.security.jackson-unsafe-deserialization": ("C1", "Injection", "high", True),
    "vendor.semgrep.java.lang.security.servletresponse-writer-xss": ("C2", "Cross-site scripting", "high", True),
    "vendor.semgrep.java.spring.security.audit.spel-injection": ("C1", "Injection", "high", True),
    "vendor.semgrep.java.spring.security.audit.spring-csrf-disabled": ("C2", "Request forgery", "medium", False),
    "vendor.semgrep.java.spring.security.audit.spring-unvalidated-redirect": ("C2", "Logic abuse", "medium", True),
    "vendor.semgrep.java.spring.security.injection.tainted-html-string": ("C2", "Cross-site scripting", "high", True),
    "vendor.semgrep.java.spring.security.injection.tainted-sql-string": ("C1", "Injection", "high", True),
    "vendor.semgrep.java.spring.security.injection.tainted-system-command": ("C1", "Injection", "high", True),
    "vendor.semgrep.java.spring.security.injection.tainted-url-host": ("C2", "Request forgery", "high", True),

    # JavaScript
    "vendor.semgrep.javascript.express.security.audit.express-cookie-session-no-httponly": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.javascript.express.security.audit.express-cookie-session-no-secure": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.javascript.express.security.audit.express-open-redirect": ("C2", "Logic abuse", "medium", True),
    "vendor.semgrep.javascript.express.security.audit.express-path-join-resolve-traversal": ("C1", "Injection", "medium", True),
    "vendor.semgrep.javascript.express.security.audit.express-session-hardcoded-secret": ("C1", "Credential exposure", "high", False),
    "vendor.semgrep.javascript.express.security.audit.express-ssrf": ("C2", "Request forgery", "medium", True),
    "vendor.semgrep.javascript.express.security.audit.xss.direct-response-write": ("C2", "Cross-site scripting", "medium", True),
    "vendor.semgrep.javascript.express.security.cors-misconfiguration": ("C3", "Defence in depth", "medium", True),
    "vendor.semgrep.javascript.express.security.express-jwt-hardcoded-secret": ("C1", "Credential exposure", "high", False),
    "vendor.semgrep.javascript.express.security.express-vm-injection": ("C1", "Injection", "high", True),
    "vendor.semgrep.javascript.express.security.injection.tainted-sql-string": ("C1", "Injection", "high", True),
    "vendor.semgrep.javascript.jsonwebtoken.security.audit.jwt-decode-without-verify": ("C1", "Authentication bypass", "medium", True),
    "vendor.semgrep.javascript.jsonwebtoken.security.hardcoded-jwt-secret": ("C1", "Credential exposure", "high", False),
    "vendor.semgrep.javascript.jsonwebtoken.security.jwt-none-alg": ("C1", "Authentication bypass", "high", True),
    "vendor.semgrep.javascript.lang.security.audit.hardcoded-hmac-key": ("C1", "Credential exposure", "high", False),
    "vendor.semgrep.javascript.lang.security.audit.md5-used-as-password": ("C2", "Weak credential storage", "high", False),
    "vendor.semgrep.javascript.lang.security.audit.path-traversal.path-join-resolve-traversal": ("C1", "Injection", "medium", True),
    "vendor.semgrep.javascript.lang.security.audit.sqli.node-mysql-sqli": ("C1", "Injection", "medium", True),
    "vendor.semgrep.javascript.lang.security.audit.sqli.node-postgres-sqli": ("C1", "Injection", "medium", True),
    "vendor.semgrep.javascript.lang.security.detect-no-csrf-before-method-override": ("C2", "Request forgery", "medium", False),

    # Kotlin
    "vendor.semgrep.kotlin.gradle.security.build-gradle-password-hardcoded": ("C1", "Credential exposure", "high", False),
    "vendor.semgrep.kotlin.lang.security.command-injection-formatted-runtime-call": ("C1", "Injection", "medium", True),
    "vendor.semgrep.kotlin.lang.security.cookie-missing-httponly": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.kotlin.lang.security.cookie-missing-secure-flag": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.kotlin.lang.security.ecb-cipher": ("C3", "Defence in depth", "high", False),
    "vendor.semgrep.kotlin.lang.security.use-of-md5": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.kotlin.lang.security.use-of-sha1": ("C3", "Defence in depth", "medium", False),

    # Python
    "vendor.semgrep.python.django.security.audit.avoid-raw-sql": ("C1", "Injection", "medium", True),
    "vendor.semgrep.python.django.security.audit.no-csrf-exempt": ("C2", "Request forgery", "medium", False),
    "vendor.semgrep.python.django.security.injection.command.command-injection-os-system": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.django.security.injection.command.subprocess-injection": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.django.security.injection.mass-assignment": ("C2", "Logic abuse", "medium", True),
    "vendor.semgrep.python.django.security.injection.open-redirect": ("C2", "Logic abuse", "medium", True),
    "vendor.semgrep.python.django.security.injection.path-traversal.path-traversal-open": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.django.security.injection.sql.sql-injection-db-cursor-execute": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.django.security.injection.ssrf.ssrf-injection-requests": ("C2", "Request forgery", "high", True),
    "vendor.semgrep.python.django.security.injection.tainted-sql-string": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.flask.security.audit.avoid_hardcoded_config_SECRET_KEY": ("C1", "Credential exposure", "high", False),
    "vendor.semgrep.python.flask.security.audit.debug-enabled": ("C3", "Defence in depth", "high", True),
    "vendor.semgrep.python.flask.security.audit.flask-cors-misconfiguration": ("C3", "Defence in depth", "medium", True),
    "vendor.semgrep.python.flask.security.audit.flask-wtf-csrf-disabled": ("C2", "Request forgery", "medium", False),
    "vendor.semgrep.python.flask.security.audit.render-template-string": ("C1", "Injection", "medium", True),
    "vendor.semgrep.python.flask.security.injection.eval-injection": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.flask.security.injection.os-system-injection": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.flask.security.injection.path-traversal-open": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.flask.security.injection.ssrf-requests": ("C2", "Request forgery", "high", True),
    "vendor.semgrep.python.flask.security.injection.subprocess-injection": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.flask.security.injection.tainted-sql-string": ("C1", "Injection", "high", True),
    "vendor.semgrep.python.flask.security.open-redirect": ("C2", "Logic abuse", "medium", True),
    "vendor.semgrep.python.lang.security.deserialization.avoid-pickle": ("C1", "Injection", "medium", True),
    "vendor.semgrep.python.lang.security.deserialization.avoid-pyyaml-load": ("C1", "Injection", "medium", True),
    "vendor.semgrep.python.lang.security.insecure-hash-algorithm-md5": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.python.lang.security.insecure-hash-algorithm-sha1": ("C3", "Defence in depth", "medium", False),
    "vendor.semgrep.python.lang.security.unverified-ssl-context": ("C2", "Data exposure", "high", False),
    "vendor.semgrep.python.requests.security.disabled-cert-validation": ("C2", "Data exposure", "high", False),
    "vendor.semgrep.python.sqlalchemy.security.sqlalchemy-sql-injection": ("C1", "Injection", "high", True),
}


# ----------------------------------------------------------------------- SonarQube rules
_APP_LANGS = ("java", "kotlin", "javascript", "typescript", "python", "go")
_APP_AND_DART = _APP_LANGS + ("dart",)
_TAINT_REPOS = (
    "java", "javasecurity", "kotlin",
    "javascript", "jssecurity", "typescript", "tssecurity",
    "python", "pythonsecurity", "go",
)


def _expand_sonar(specs: list[tuple[tuple[str, ...], str, RuleEntry]]) -> dict[str, RuleEntry]:
    out: dict[str, RuleEntry] = {}
    for repos, code, entry in specs:
        for repo in repos:
            out[f"{repo}:{code}"] = entry
    return out


SONAR_RULES: dict[str, RuleEntry] = _expand_sonar([
    # Hard-coded credentials and secrets
    (_APP_AND_DART, "S6437", ("C1", "Credential exposure", "high", False)),
    (_APP_AND_DART, "S2068", ("C1", "Credential exposure", "medium", False)),
    (_APP_AND_DART + ("secrets", "docker"), "S6418", ("C1", "Credential exposure", "high", False)),
    (("secrets",), "S6290", ("C1", "Credential exposure", "high", False)),
    (("secrets",), "S6334", ("C1", "Credential exposure", "high", False)),
    (("secrets",), "S6697", ("C1", "Credential exposure", "high", False)),

    # SQL, OS command, code, LDAP, XPath and NoSQL injection
    (_TAINT_REPOS, "S3649", ("C1", "Injection", "high", True)),
    (_APP_AND_DART, "S2077", ("C1", "Injection", "medium", True)),  # SQL formatting hotspot
    (_TAINT_REPOS, "S2076", ("C1", "Injection", "high", True)),
    (_APP_AND_DART, "S4721", ("C1", "Injection", "medium", True)),  # OS command execution hotspot
    (_TAINT_REPOS, "S5334", ("C1", "Injection", "high", True)),  # dynamic code execution
    (("java", "kotlin", "javascript", "typescript", "python"), "S1523", ("C1", "Injection", "medium", True)),
    (("java", "javasecurity", "kotlin", "python", "pythonsecurity"), "S2078", ("C1", "Injection", "high", True)),
    (("java", "javasecurity", "kotlin", "python", "pythonsecurity"), "S2091", ("C1", "Injection", "high", True)),
    (_TAINT_REPOS, "S5147", ("C1", "Injection", "high", True)),  # NoSQL injection

    # Path traversal, XXE and unsafe deserialisation
    (_TAINT_REPOS, "S2083", ("C1", "Injection", "high", True)),  # path traversal
    (("java", "kotlin", "javascript", "typescript", "python", "xml"), "S2755", ("C1", "Injection", "high", True)),  # XXE
    (_TAINT_REPOS, "S5135", ("C1", "Injection", "high", True)),  # unsafe deserialisation
    (("java", "kotlin", "python"), "S4508", ("C1", "Injection", "medium", True)),  # deserialisation hotspot

    # Authentication and JWT
    (_APP_LANGS, "S5659", ("C1", "Authentication bypass", "high", True)),  # insecure JWT signing or verification
    (("java", "kotlin"), "S5808", ("C1", "Authentication bypass", "medium", True)),  # permissive authorizer/voter
    (("java", "kotlin", "javascript", "typescript", "python"), "S4834", ("C1", "Authentication bypass", "medium", True)),

    # SSRF, open redirect, XSS and CSRF
    (_TAINT_REPOS, "S5144", ("C2", "Request forgery", "high", True)),  # SSRF
    (_TAINT_REPOS, "S5146", ("C2", "Logic abuse", "high", True)),  # open redirect
    (_TAINT_REPOS, "S5131", ("C2", "Cross-site scripting", "high", True)),  # XSS
    (("javascript", "typescript"), "S6299", ("C2", "Cross-site scripting", "medium", True)),  # unescaped HTML hotspot
    (("java", "kotlin", "javascript", "typescript", "python"), "S5247", ("C2", "Cross-site scripting", "medium", True)),
    (_APP_LANGS, "S4502", ("C2", "Request forgery", "medium", False)),  # CSRF protection disabled

    # CORS, crypto, TLS, certificate and hostname checks
    (_APP_LANGS, "S5122", ("C3", "Defence in depth", "medium", True)),  # permissive CORS
    (_APP_AND_DART, "S4790", ("C3", "Defence in depth", "medium", False)),  # weak hash hotspot
    (_APP_AND_DART, "S5547", ("C3", "Defence in depth", "high", False)),  # weak cipher
    (_APP_AND_DART, "S5542", ("C3", "Defence in depth", "high", False)),  # insecure encryption mode/padding
    (_APP_AND_DART, "S4426", ("C3", "Defence in depth", "high", False)),  # weak cryptographic key length
    (_APP_AND_DART, "S4423", ("C3", "Defence in depth", "high", False)),  # weak TLS protocol
    (_APP_LANGS, "S3329", ("C3", "Defence in depth", "high", False)),  # static IV
    (_APP_AND_DART, "S4830", ("C2", "Data exposure", "high", False)),  # disabled certificate validation (active MITM)
    (_APP_AND_DART, "S5527", ("C2", "Data exposure", "high", False)),  # disabled hostname verification (active MITM)

    # Weak PRNG, debug features, clear-text protocols, cookies, ReDoS and archives
    (_APP_AND_DART, "S2245", ("C3", "Defence in depth", "medium", False)),  # PRNG hotspot
    (_APP_AND_DART, "S4507", ("C3", "Defence in depth", "medium", True)),  # debug features hotspot
    (_APP_AND_DART + ("docker",), "S5332", ("C3", "Defence in depth", "medium", False)),  # clear-text protocol
    (_APP_LANGS + ("Web",), "S2092", ("C3", "Defence in depth", "medium", False)),  # cookie without Secure
    (_APP_LANGS + ("Web",), "S3330", ("C3", "Defence in depth", "medium", False)),  # cookie without HttpOnly
    (_APP_AND_DART, "S5852", ("C3", "Defence in depth", "medium", True)),  # ReDoS hotspot
    (_TAINT_REPOS, "S2631", ("C3", "Defence in depth", "high", True)),  # regex injection / ReDoS
    (_APP_LANGS, "S5042", ("C3", "Defence in depth", "medium", True)),  # archive expansion / zip bomb
    (_TAINT_REPOS, "S5145", ("C3", "Defence in depth", "medium", True)),  # log injection

    # Docker container user/root and secret checks
    (("docker",), "S6471", ("C3", "Defence in depth", "high", False)),  # running container as root
    (("docker",), "S6504", ("C3", "Defence in depth", "medium", False)),  # recursive copy in Dockerfile
    (("docker",), "S6505", ("C3", "Defence in depth", "medium", False)),  # package manager scripts
    (("docker",), "S6506", ("C3", "Defence in depth", "medium", False)),  # package manager hardening
    (("docker",), "S7019", ("C3", "Defence in depth", "medium", False)),  # remote archive ADD
    (("docker",), "S7020", ("C3", "Defence in depth", "high", False)),  # unsafe privileges / sudo in container
    (("docker",), "S7031", ("C1", "Credential exposure", "high", False)),  # secret in Dockerfile ENV/ARG

    # Hygiene
    (_APP_AND_DART + ("docker",), "S1313", ("C4", "Hygiene", "medium", False)),  # hard-coded IP address
])


# ----------------------------------------------------------------------- CWE fallback
# Fallback entries use medium precision because the underlying rule is not audited here.
CWE: dict[str, RuleEntry] = {
    # C1 Direct compromise
    "CWE-620": ("C1", "Account takeover", "medium", True),
    "CWE-640": ("C1", "Account takeover", "medium", True),
    "CWE-287": ("C1", "Authentication bypass", "medium", True),
    "CWE-288": ("C1", "Authentication bypass", "medium", True),
    "CWE-290": ("C1", "Authentication bypass", "medium", True),
    "CWE-306": ("C1", "Authentication bypass", "medium", True),
    "CWE-347": ("C1", "Authentication bypass", "medium", True),
    "CWE-862": ("C1", "Authentication bypass", "medium", True),
    "CWE-863": ("C1", "Authentication bypass", "medium", True),
    "CWE-259": ("C1", "Credential exposure", "medium", False),
    "CWE-260": ("C1", "Credential exposure", "medium", False),
    "CWE-321": ("C1", "Credential exposure", "medium", False),
    "CWE-798": ("C1", "Credential exposure", "medium", False),
    "CWE-1392": ("C1", "Credential exposure", "medium", False),
    "CWE-22": ("C1", "Injection", "medium", True),
    "CWE-73": ("C1", "Injection", "medium", True),
    "CWE-77": ("C1", "Injection", "medium", True),
    "CWE-78": ("C1", "Injection", "medium", True),
    "CWE-89": ("C1", "Injection", "medium", True),
    "CWE-90": ("C1", "Injection", "medium", True),
    "CWE-91": ("C1", "Injection", "medium", True),
    "CWE-94": ("C1", "Injection", "medium", True),
    "CWE-95": ("C1", "Injection", "medium", True),
    "CWE-96": ("C1", "Injection", "medium", True),
    "CWE-502": ("C1", "Injection", "medium", True),
    "CWE-611": ("C1", "Injection", "medium", True),
    "CWE-917": ("C1", "Injection", "medium", True),
    "CWE-943": ("C1", "Injection", "medium", True),
    "CWE-1336": ("C1", "Injection", "medium", True),

    # C2 Data or logic abuse
    "CWE-312": ("C2", "Data exposure", "medium", False),
    "CWE-532": ("C2", "Data exposure", "medium", False),
    "CWE-552": ("C2", "Data exposure", "medium", True),
    "CWE-639": ("C2", "Data exposure", "medium", True),
    "CWE-269": ("C2", "Logic abuse", "medium", True),
    "CWE-285": ("C2", "Logic abuse", "medium", True),
    "CWE-362": ("C2", "Logic abuse", "medium", True),
    "CWE-367": ("C2", "Logic abuse", "medium", True),
    "CWE-501": ("C2", "Logic abuse", "medium", True),
    "CWE-601": ("C2", "Logic abuse", "medium", True),
    "CWE-807": ("C2", "Logic abuse", "medium", True),
    "CWE-840": ("C2", "Logic abuse", "medium", True),
    "CWE-915": ("C2", "Logic abuse", "medium", True),
    "CWE-1321": ("C2", "Logic abuse", "medium", True),
    "CWE-352": ("C2", "Request forgery", "medium", False),
    "CWE-918": ("C2", "Request forgery", "medium", True),
    "CWE-1385": ("C2", "Request forgery", "medium", False),
    "CWE-79": ("C2", "Cross-site scripting", "medium", True),
    "CWE-80": ("C2", "Cross-site scripting", "medium", True),
    "CWE-256": ("C2", "Weak credential storage", "medium", False),
    "CWE-257": ("C2", "Weak credential storage", "medium", False),
    "CWE-522": ("C2", "Weak credential storage", "medium", False),
    "CWE-916": ("C2", "Weak credential storage", "medium", False),

    # C3 Defence in depth
    "CWE-117": ("C3", "Defence in depth", "medium", True),
    "CWE-200": ("C3", "Defence in depth", "medium", True),
    "CWE-208": ("C3", "Defence in depth", "medium", False),
    "CWE-209": ("C3", "Defence in depth", "medium", True),
    "CWE-215": ("C3", "Defence in depth", "medium", True),
    "CWE-250": ("C3", "Defence in depth", "medium", False),
    "CWE-295": ("C2", "Data exposure", "medium", False),
    "CWE-297": ("C2", "Data exposure", "medium", False),
    "CWE-307": ("C3", "Defence in depth", "medium", True),
    "CWE-319": ("C3", "Defence in depth", "medium", False),
    "CWE-326": ("C3", "Defence in depth", "medium", False),
    "CWE-327": ("C3", "Defence in depth", "medium", False),
    "CWE-328": ("C3", "Defence in depth", "medium", False),
    "CWE-329": ("C3", "Defence in depth", "medium", False),
    "CWE-330": ("C3", "Defence in depth", "medium", False),
    "CWE-338": ("C3", "Defence in depth", "medium", False),
    "CWE-346": ("C3", "Defence in depth", "medium", True),
    "CWE-400": ("C3", "Defence in depth", "medium", True),
    "CWE-489": ("C3", "Defence in depth", "medium", True),
    "CWE-614": ("C3", "Defence in depth", "medium", False),
    "CWE-693": ("C3", "Defence in depth", "medium", True),
    "CWE-770": ("C3", "Defence in depth", "medium", True),
    "CWE-942": ("C3", "Defence in depth", "medium", True),
    "CWE-1004": ("C3", "Defence in depth", "medium", False),
    "CWE-1333": ("C3", "Defence in depth", "medium", True),
    "CWE-1357": ("C3", "Defence in depth", "medium", False),

    # C4 Hygiene
    "CWE-547": ("C4", "Hygiene", "medium", False),
}


# ----------------------------------------------------------------------- key normalisation
_OPENGREP_PREFIXES = ("external_opengrep:", "opengrep:")
# Mirrors EXTERNAL_ID in tools/sdt_to_docx.py and _rule_key in tools/sdt_to_sonar.py.
_EXTERNAL_SDT = re.compile(
    r"^external_sdt-(?P<adapter>[A-Za-z0-9_.-]+):sdt-(?P=adapter)-(?P<id>[A-Za-z0-9_.-]+)-(?P<hash>[0-9a-f]{16})$"
)
_BARE_SDT = re.compile(
    r"^sdt-(?P<adapter>endpoints|opengrep|gitleaks|trivy-fs|trivy-image|trivy)-(?P<id>[A-Za-z0-9_.-]+)-(?P<hash>[0-9a-f]{16})$"
)
_EXTERNAL_SDT_PLAIN = re.compile(r"^external_sdt-(?P<adapter>[A-Za-z0-9_.-]+):(?P<rest>.+)$")
_CWE_NUMBER = re.compile(r"(?i)\b(?:cwe-)?(\d+)\b")


def _sonar_digest(adapter: str, rule_id: str) -> str:
    return hashlib.sha256(f"{adapter}\0{rule_id}".encode()).hexdigest()[:16]


def _build_digest_index() -> dict[tuple[str, str], str]:
    index: dict[tuple[str, str], str] = {}
    for rule_id in RULES:
        adapter = "endpoints" if rule_id.startswith("scp.endpoints.") else "opengrep"
        index[(adapter, _sonar_digest(adapter, rule_id))] = rule_id
    for rule_id in VENDOR_RULES:
        index[("opengrep", _sonar_digest("opengrep", rule_id))] = rule_id
    return index


_DIGEST_INDEX: dict[tuple[str, str], str] = _build_digest_index()


def normalize_rule_key(rule: str) -> str:
    """Normalise a SonarQube or SDT external rule key back to its canonical rule id."""
    key = (rule or "").strip()
    if not key:
        return ""
    for prefix in _OPENGREP_PREFIXES:
        if key.startswith(prefix):
            return key[len(prefix):]

    match = _EXTERNAL_SDT.fullmatch(key) or _BARE_SDT.fullmatch(key)
    if match:
        adapter = match.group("adapter")
        tail = match.group("id")
        digest = match.group("hash")
        exact = _DIGEST_INDEX.get((adapter, digest))
        if exact:
            return exact
        if adapter == "endpoints":
            if tail.startswith("scp.endpoints."):
                return tail
            candidate = f"scp.endpoints.{tail}"
            if candidate in RULES:
                return candidate
        return tail

    plain = _EXTERNAL_SDT_PLAIN.fullmatch(key)
    if plain:
        adapter = plain.group("adapter")
        rest = plain.group("rest")
        if rest in RULES or rest in VENDOR_RULES:
            return rest
        if adapter == "endpoints":
            candidate = rest if rest.startswith("scp.endpoints.") else f"scp.endpoints.{rest}"
            if candidate in RULES:
                return candidate
        return rest

    return key


def _normalize_cwe(raw: str) -> str:
    match = _CWE_NUMBER.search(str(raw or ""))
    return f"CWE-{int(match.group(1))}" if match else ""


def _make_impact(entry: RuleEntry, source: str, kind: str = "") -> Impact:
    klass, label, precision, needs_reach = entry
    if not precision:
        precision = "medium" if kind.strip().lower() == "security hotspot" else "high"
    return Impact(
        klass=klass,
        label=label,
        precision=precision,
        needs_reach=needs_reach,
        source=source,
    )


def classify(
    rule: str,
    name: str = "",
    cwe: tuple[str, ...] = (),
    kind: str = "",
) -> Impact | None:
    """Return the Impact for a code finding, or None when no table covers it."""
    del name  # reserved for callers that pass rule metadata; classification is table-driven
    key = normalize_rule_key(rule)
    if key in RULES:
        return _make_impact(RULES[key], "rule", kind)
    if key in VENDOR_RULES:
        return _make_impact(VENDOR_RULES[key], "rule", kind)
    if key in SONAR_RULES:
        return _make_impact(SONAR_RULES[key], "sonar", kind)

    best: RuleEntry | None = None
    for raw_cwe in cwe or ():
        cid = _normalize_cwe(raw_cwe)
        entry = CWE.get(cid)
        if entry is None:
            continue
        if best is None or CLASS_CEILING[entry[0]] < CLASS_CEILING[best[0]]:
            best = entry
    if best is not None:
        klass, label, precision, needs_reach = best
        if kind.strip().lower() == "security hotspot":
            precision = "medium"
        return Impact(
            klass=klass,
            label=label,
            precision=precision,
            needs_reach=needs_reach,
            source="cwe",
        )
    return None
