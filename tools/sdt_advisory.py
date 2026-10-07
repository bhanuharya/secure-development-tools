#!/usr/bin/env python3
"""Deterministic advisory for code-security findings: no model, same input -> same output.

Every code finding gets an Assessment, Evidence, what to check, and what to do, in the
same shape as the optional model review (sdt_triage_codex.py), which replaces it for the
findings the model reviewed. The rules here only conclude "false positive" or "real
issue" on strong, checkable signals in the flagged line; everything else gets a fixed,
rule-specific manual check, so a developer always knows what to look at.
"""
from __future__ import annotations

import re
from pathlib import Path

TEST_PATH = re.compile(r"(^|/)(test|tests|spec|__tests__|integration_test|mock|mocks|example|examples)(/|$)"
                       r"|[._-](test|spec|mock)\.[a-z]+$", re.I)
SENSITIVE_NAME = re.compile(r"(?i)\b\w*(pin|password|passwd|secret|token|otp|credential|authorization|cookie)\w*\b")
LOG_CALL = re.compile(r"\b(print|debugPrint|log|developer\.log|console\.log|Log\.[dievw]|logger\.\w+|\w*[Ll]ogger\.\w+)\s*\(")
INTERPOLATION = re.compile(r"\$\{?\w|\+\s*\w|,\s*\w|%s|\{\}")
LOCAL_URL = re.compile(r"http://(localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|www\.w3\.org/|schemas\.|ns\.adobe\.com/)")
UI_RANDOM = re.compile(r"(?i)skeleton|placeholder|shimmer|animat|color|colour|notification|jitter|delay|backoff|demo|sample|shuffle")

# Likely secret values: never sent, whatever file they are in.
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\b(ghp|gho|ghu|ghs|github_pat)_[0-9A-Za-z_]{20,}\b"),
    re.compile(r"\bxox[abposr]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\b(sk|rk|pk)_(live|test)_[0-9A-Za-z]{10,}\b"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    re.compile(r"\bsqu_[0-9a-f]{20,}\b"),
]
SECRET_WORD = r"password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credentials?"
SECRET_ASSIGNMENT = re.compile(
    rf"""(?i)((?:{SECRET_WORD}|auth)["']?\s*[:=]\s*)(["'])([^"'\s]+)\2""")
# Values that say "a secret goes here" rather than being one. They stay readable: seeing that the flagged
# "password" is the word password, changeit or ${DB_PASSWORD} is how a reviewer recognises a false positive.
PLACEHOLDER = re.compile(r"""(?ix)^(?: pass(?:word|wd)? | pwd | secret | changeit | change[-_ ]?me | admin | root
    | test(?:ing)? | example | sample | dummy | default | none | null | nil | empty | todo | true | false
    | your[-_ ]?[\w-]* | x{3,} | \*{3,} | \.{3,} | <[^>]*> | \$\{[^}]*\} | \{\{[^}]*\}\} | %\([^)]*\)s
    | \$[A-Za-z_][A-Za-z0-9_]* | \#\{[^}]*\} | \[REDACTED\] )$""")
# Settings files, where a value is not quoted: "password: x", "db.password=x", "<password>x</password>".
CONFIG_FILE = re.compile(r"(?i)(\.(ya?ml|properties|env|conf|cfg|ini|toml|xml|json)$|(^|/)\.env[\w.-]*$|\.env\.[\w.-]+$)")
CONFIG_VALUE = re.compile(
    rf"""(?ix)^(?P<head>\s*(?:-\s+)?(?:export\s+)?["']?[\w.\-/\[\]]*?(?:{SECRET_WORD})["']?\s*[:=]\s*)
         (?P<quote>["']?)(?P<value>[^"'\s#][^#]*?)(?P=quote)(?P<tail>\s*(?:\#.*)?)$""")
XML_VALUE = re.compile(rf"(?i)(<(?P<tag>[\w.:-]*(?:{SECRET_WORD}))>)(?P<value>[^<]+)(</(?P=tag)>)")
# How the AI review words it: "sets the password to the literal `x`", "the token `x`".
PROSE_VALUE = re.compile(rf"(?i)((?:\bliteral(?:\s+value)?|\b(?:{SECRET_WORD})(?:\s+(?:is|of|to|as))?)\s+)`([^`\n]+)`")
URL_PASSWORD = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/\s:@\"']+:)([^@\s/\"']+)(@)", re.I)
ANY_CONFIG_VALUE = re.compile(
    r"""(?x)^(?P<head>\s*(?:-\s+)?(?:export\s+)?["']?[\w.\-/\[\]]+["']?\s*[:=]\s*)
        (?P<quote>["']?)(?P<value>[^"'\s#][^#]*?)(?P=quote)(?P<tail>\s*(?:\#.*)?)$""")
CREDENTIAL_RULE = re.compile(r"(?i)S6437|S2068|S6418|S6290|hardcoded|hard-coded|secrets?[.:-]|private-key")
QUOTED = re.compile(r"""(["'])((?:(?!\1).)+)\1""")


def _kept(value: str) -> bool:
    return bool(PLACEHOLDER.match(value.strip()))


def redact(text: str, path: str = "", withheld: set | None = None) -> str:
    """The code with likely secret values replaced by [REDACTED]; placeholders are left as they are.
    Give the file's path when there is one: in settings files unquoted values are covered too.
    The values taken out are added to `withheld` when a set is given."""
    def hide(value: str, shown: str, hidden: str) -> str:
        if _kept(value):
            return shown
        if withheld is not None:
            withheld.add(value.strip())
        return hidden

    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = SECRET_ASSIGNMENT.sub(
        lambda m: hide(m.group(3), m.group(0), f"{m.group(1)}{m.group(2)}[REDACTED]{m.group(2)}"), text)
    text = PROSE_VALUE.sub(lambda m: hide(m.group(2), m.group(0), f"{m.group(1)}`[REDACTED]`"), text)
    text = URL_PASSWORD.sub(lambda m: hide(m.group(2), m.group(0), f"{m.group(1)}[REDACTED]{m.group(3)}"), text)
    if path and CONFIG_FILE.search(path):
        lines = []
        for line in text.split("\n"):
            line = XML_VALUE.sub(lambda m: hide(m.group("value"), m.group(0), f"{m.group(1)}[REDACTED]{m.group(4)}"), line)
            found = CONFIG_VALUE.match(line)
            if found:
                line = hide(found.group("value"), line,
                            f"{found.group('head')}{found.group('quote')}[REDACTED]{found.group('quote')}{found.group('tail')}")
            lines.append(line)
        text = "\n".join(lines)
    return text


def redact_credential_line(line: str, path: str = "", withheld: set | None = None) -> str:
    """The line a credential rule flagged: every quoted value on it is withheld as well, because the rule
    says one of them is the credential (new Login("app", "s3cret") names no password)."""
    def hide(value: str, shown: str, hidden: str) -> str:
        if _kept(value):
            return shown
        if withheld is not None:
            withheld.add(value.strip())
        return hidden

    line = redact(line, path, withheld)
    found = ANY_CONFIG_VALUE.match(line) if path and CONFIG_FILE.search(path) else None
    if found:  # a settings line: whatever its name, the value is the credential
        return hide(found.group("value"), line,
                    f"{found.group('head')}{found.group('quote')}[REDACTED]{found.group('quote')}{found.group('tail')}")
    return QUOTED.sub(lambda m: hide(m.group(2), m.group(0), f"{m.group(1)}[REDACTED]{m.group(1)}"), line)


def redact_lines(lines: dict[int, str], path: str = "", flagged: frozenset | set = frozenset()) -> dict[int, str]:
    """An excerpt (line number -> text) as a report or a prompt may show it. A value withheld on one line is
    withheld on the others too: a user name equal to the password would otherwise give it away. On the lines
    in `flagged` (those a credential rule reported) every value is withheld."""
    withheld: set = set()
    shown = {number: redact_credential_line(text, path, withheld) if number in flagged else redact(text, path, withheld)
             for number, text in lines.items()}
    for value in sorted((v for v in withheld if len(v) >= 3), key=len, reverse=True):
        again = re.compile(r"(?<![\w-])" + re.escape(value) + r"(?![\w-])")
        shown = {number: again.sub("[REDACTED]", text) for number, text in shown.items()}
    return shown


# rule key pattern -> (what to check to decide, fix if it is real, what to record if it is safe)
RULE_CHECKS = [
    (re.compile(r"S6299|v-html|vue.*escap"),
     "Check the bound value: safe if it is a constant, an i18n string, or a URL that passed your allow-list "
     "validator; a real issue if it carries user or API data into v-html, innerHTML or an href.",
     "Render text with {{ }} instead of v-html, and pass every dynamic href through one allow-list validator.",
     "bound value is constant or passes the URL allow-list validator"),
    (re.compile(r"webview.*(javascript|channel)|javascript-channel"),
     "Find the URL this WebView loads (initialUrl / loadRequest) and its navigation handler. It is safe if it only "
     "loads constant https URLs on your own domains and blocks navigation elsewhere.",
     "Restrict navigation to an allow-list of your domains and treat channel messages as untrusted input.",
     "WebView loads only fixed first-party https URLs; navigation restricted"),
    (re.compile(r"deeplink|dynamic.?link|unvalidated-handler"),
     "Follow the link handler: check that scheme, host and parameters are validated before they reach navigation, "
     "a WebView, or an API call.",
     "Validate scheme and host against an allow-list and parse parameters strictly before use.",
     "deep link data validated against an allow-list before use"),
    (re.compile(r"random|S2245"),
     "Check what the random value is used for. Safe for UI, animation, placeholders or local notification ids; "
     "a real issue for tokens, OTPs, nonces, passwords or ids sent to a server.",
     "Use Random.secure() (Dart) or a cryptographic RNG for security values.",
     "random value used only for UI/local ids, not security"),
    (re.compile(r"hardcoded-api-key|hard-coded|S6418|S2068|secrets:"),
     "Decide what the literal is: a public client key (restrict it by API and app in the provider console) or a "
     "secret (rotate it and move it to the backend).",
     "Remove the literal; fetch credentials at runtime from an authenticated backend.",
     "public client key, restricted by API and app"),
    (re.compile(r"logging|sensitive-data|S4792"),
     "Check the logged values: safe if the message is static text; a real issue if a PIN, password, token or "
     "personal data is logged.",
     "Remove the log statement or log a redacted form; strip debug logging from release builds.",
     "static log message, no sensitive data"),
    (re.compile(r"cleartext|S5332"),
     "Check the URL or setting: safe for local development hosts and XML namespaces; a real issue if the app sends "
     "data to that host over http in release builds.",
     "Use https, or limit cleartext to debug builds with a network security config.",
     "not a network endpoint (local host or namespace)"),
    (re.compile(r"S6358|allowBackup|allow-backup"),
     "Check whether the app stores tokens or personal data in files that Android backups include.",
     "Set android:allowBackup=\"false\" or exclude sensitive files with dataExtractionRules.",
     "no sensitive data in backed-up storage"),
    (re.compile(r"S5604|permission"),
     "Check that a shipped feature needs this permission; remove it if nothing uses it.",
     "Remove unused permissions from AndroidManifest.xml.",
     "permission required by a documented feature"),
    (re.compile(r"S5852|regex|redos"),
     "Check whether untrusted, unbounded input reaches this regular expression.",
     "Rewrite the pattern without nested or overlapping quantifiers, or bound the input length.",
     "input is bounded or not attacker-controlled"),
    (re.compile(r"crypto|md5|sha1|ecb|static-iv|zero-key|S4790|S5547"),
     "Check whether this hash or cipher protects security data (passwords, tokens, integrity) or only builds "
     "cache keys or checksums.",
     "Use SHA-256+/bcrypt/Argon2 for security data and AES-GCM with a random IV.",
     "non-security use (cache key / checksum)"),
]
GENERIC = ("Trace the value used at the flagged line back to its source: it is a false positive if it is a constant "
           "or app-internal value, a real issue if it comes from user, network, deep-link or file input.",
           "Apply the rule's recommendation shown above.",
           "value is constant or app-internal")


def _line(src_root: Path | None, path: str, line: int) -> str:
    if not src_root or not path or line < 1:
        return ""
    root = src_root.resolve()
    target = (root / path).resolve()
    if root not in target.parents or not target.is_file():
        return ""
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1].strip() if line <= len(lines) else ""


def _checks(rule: str) -> tuple[str, str, str]:
    for pattern, check, fix, record in RULE_CHECKS:
        if pattern.search(rule):
            return check, fix, record
    return GENERIC


def _nearby(src_root: Path | None, path: str, line: int, radius: int = 3) -> str:
    return "\n".join(_line(src_root, path, n) for n in range(max(1, line - radius), line + radius + 1))


def assess(rule: str, path: str, line: int, src_root: Path | None) -> dict:
    """A deterministic advisory note for one code finding."""
    check, fix, record = _checks(rule)
    text = _line(src_root, path, line)
    where = f"line {line}" if line else "this finding"

    def note(verdict, reason, check_text, action):
        return {"verdict": verdict, "confidence": "rule-based", "reason": reason, "check": check_text,
                "suggested_fix": action, "source": "rules"}

    if path and TEST_PATH.search(path):
        return note("likely_false_positive", f"{path} is test or example code.",
                    "Confirm this file is not compiled into the release app.", "test code, not shipped")
    if text and re.search(r"logging|sensitive-data|S4792", rule) and LOG_CALL.search(text):
        names = sorted({m.group(0) for m in SENSITIVE_NAME.finditer(text.split("(", 1)[-1])})
        if names and INTERPOLATION.search(text):
            return note("likely_true_positive", f"The log call at {where} includes {', '.join(names[:3])}.",
                        "Confirm these values hold user secrets (PIN, password, token) at runtime.", fix)
        if not INTERPOLATION.search(text.split("(", 1)[-1]):
            return note("likely_false_positive", f"The log call at {where} writes a fixed message with no variables.",
                        "Confirm the message stays static.", record)
    if text and re.search(r"cleartext|S5332", rule) and LOCAL_URL.search(text):
        return note("likely_false_positive", f"The http URL at {where} is a local host or XML namespace, not an endpoint.",
                    "Confirm it is never used as a request URL.", record)
    if text and re.search(r"random|S2245", rule) and UI_RANDOM.search(_nearby(src_root, path, line)):
        return note("likely_false_positive",
                    f"The random value near {where} feeds UI or local notification code (placeholder/animation/id).",
                    "Confirm the value never becomes a token, OTP, nonce or server-side id.", record)
    return note("needs_context", f"The rule matched {where}; the code alone does not settle it." if not text else
                f"The rule matched {where}: {(redact_credential_line(text, path) if CREDENTIAL_RULE.search(rule) else redact(text, path))[:160]}", check, f"If safe: mark Safe - \"{record}\". Otherwise: {fix}")
