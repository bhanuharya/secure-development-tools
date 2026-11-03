#!/usr/bin/env python3
"""How soon to act on a finding: P1 (now) to P4 (when the code is touched anyway).

Severity says how bad a weakness is in general. Priority starts there and moves one step at a
time for what is known about this repository and this finding:

  * where the service runs: reachable from the internet, or only from an internal network;
  * how much the business depends on it;
  * where in the repository the finding sits: shipped code, files served to browsers, or
    tests, examples and documentation that never ship;
  * what was found out about the finding: the review judged it real, the package is not
    imported, the secret is a working credential by its format.

Every step is kept with its reason, so the report can say why a finding has its priority.

Guardrails (docs/adr/0009-finding-priority.md):
  * A fact that is not known never lowers a priority. A repository whose exposure is not
    recorded is treated as reachable from the internet.
  * What is known about the context lowers a finding by at most two steps. Nothing is
    dropped, and the severity stays next to the priority.
  * A review's opinion can raise a finding, never lower it. Lowering on a "false positive"
    opinion is a reviewer's decision, recorded in SonarQube, which takes the finding out of
    the report altogether.
  * The service's exposure does not lower secrets, nor rules about hard-coded credentials,
    cryptography or certificate checks: those do not need an attacker to reach the service.

Standard library only.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

LEVELS = ("P1", "P2", "P3", "P4")
MEANING = {"P1": "act now", "P2": "fix in the current release", "P3": "plan the fix", "P4": "fix when the code is touched"}
SEVERITY_LEVEL = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 3}
MAX_LOWER = 2

EXPOSURES = ("internet", "internal", "none", "unknown")
CRITICALITIES = ("high", "normal", "low")
VISIBILITIES = ("private", "public")
EXPOSURE_TEXT = {"internet": "reachable from the internet", "internal": "internal network only",
                 "none": "not deployed as a service", "unknown": "not recorded"}

# Files that never ship: tests, mocks, fixtures, examples, documentation. A secret in them is
# still a secret, so they lower one step and no more.
NOT_SHIPPED = re.compile(
    r"(^|/)(tests?|specs?|__tests__|__mocks__|mocks?|fixtures?|testdata|test-?data|e2e|cypress|playwright|"
    r"integration_test|examples?|samples?|docs?|documentation|stories|\.storybook|benchmarks?)(/|$)"
    r"|[._-](test|spec|stories)\.[a-z0-9]+$|(^|/)test_[^/]+\.py$|(^|/)conftest\.py$", re.I)
# Files a web server hands to every visitor: whatever they hold is public.
SERVED = re.compile(r"(^|/)(public|static|wwwroot|www|htdocs|dist)/|\.html?$", re.I)

# Code rules an attacker exploits by reaching the service (their own input, a debug or dev server):
# the service's exposure decides how many people can. Matched on the rule key and the rule's name
# (SonarQube names are sentences).
# Cross-site request forgery is left out on purpose: it rides on an internal user's browser, so an
# internal service is as exposed to it as a public one.
REACH_NEEDED = re.compile(
    r"(?i)inject|sqli|\bsql\b|xss|cross.site.script|escap|v-html|innerhtml|dangerously|ssrf|server.side.request"
    r"|traversal|zip.?slip|redirect|deseriali[sz]|unseriali[sz]|pickle|xxe|external.entit|tainted"
    r"|command|\bexec|\beval\b|template|ssti|ldap|xpath|prototype.pollution|regular.expression|redos"
    r"|\bregex|mass.assign|upload|dev-server|debug")
# Hard-coded credentials: whoever reads the code has them, whatever the service. No fact about the
# service lowers them.
CREDENTIAL_CODE = re.compile(
    r"(?i)S6437|S2068|S6418|S6290|hardcoded|hard-coded|credential|password|secrets?[.:-]|private-key")
# Weaknesses that hurt without anyone reaching the service: not lowered for an internal service.
NO_ATTACKER_NEEDED = re.compile(r"(?i)crypt|cipher|hash|random|certificate|\btls\b|\bssl\b")
# Secret kinds that say nothing about what the value unlocks.
GENERIC_SECRET = re.compile(r"(?i)^(generic|jwt$|jwt-|secret$)")
# Names that say what a generic secret unlocks: it signs sessions or tokens, or it is a password.
# Matched on the scanner's redacted match ("ADMIN_JWT_SECRET', '[REDACTED]'"), never on a value.
SIGNING_OR_PASSWORD_NAME = re.compile(
    r"(?i)(jwt|session|signing|cookie|encryption|master|app)[_.-]?(secret|key)s?|secret[_.-]?key(?![_.-]?(id|name))"
    r"|salt|pass(word|wd)|(^|[^a-z])pwd([^a-z]|$)|private[_.-]?key")


@dataclass(frozen=True)
class Context:
    """What is known about the repository and the service it runs as."""
    exposure: str = "unknown"
    criticality: str = "normal"
    visibility: str = "private"
    source: str = ""  # where the facts come from, e.g. "inventory", "--exposure"

    @property
    def internal(self) -> bool:
        return self.exposure in ("internal", "none")


@dataclass(frozen=True)
class Step:
    reason: str
    change: int  # -1 raises (towards P1), +1 lowers (towards P4)

    def __str__(self) -> str:
        return f"{self.reason} {'↑' if self.change < 0 else '↓'}"


@dataclass(frozen=True)
class Priority:
    level: str
    base: str  # what the level started from, e.g. "High severity"
    steps: tuple = ()

    @property
    def rank(self) -> int:
        return LEVELS.index(self.level)

    @property
    def why(self) -> str:
        return "; ".join([self.base, *map(str, self.steps)])

    def __str__(self) -> str:
        return f"{self.level} ({self.why})"


def decide(start: int, base: str, raises: list[str], lowers: list[str]) -> Priority:
    """The level from a starting index, the raising and the lowering facts (at most MAX_LOWER apply)."""
    lowers = lowers[:MAX_LOWER]
    index = min(len(LEVELS) - 1, max(0, start - len(raises) + len(lowers)))
    steps = tuple(Step(r, -1) for r in raises) + tuple(Step(r, +1) for r in lowers)
    return Priority(LEVELS[index], base, steps)


def place(path: str) -> str:
    """'not shipped', 'served' or 'shipped' for a repository path."""
    if path and NOT_SHIPPED.search(path):
        return "not shipped"
    if path and SERVED.search(path):
        return "served"
    return "shipped"


def _severity(severity: str) -> tuple[int, str]:
    severity = severity if severity in SEVERITY_LEVEL else "Medium"
    return SEVERITY_LEVEL[severity], f"{severity} severity"


def _service(ctx: Context, lowers: list[str]) -> None:
    """The lowering facts about the service itself, shared by code and dependencies."""
    if ctx.internal and ctx.criticality != "high":
        lowers.append("internal service" if ctx.exposure == "internal" else "not deployed as a service")
    if ctx.criticality == "low":
        lowers.append("low business criticality")


def code(rule: str, name: str, severity: str, path: str, verdict: str = "", confidence: str = "",
         ctx: Context = Context()) -> Priority:
    """A code finding (SonarQube issue or hotspot, OpenGrep match)."""
    start, base = _severity(severity)
    raises, lowers = [], []
    if verdict == "likely_true_positive" and str(confidence).lower() != "low":
        raises.append("review judged it real")
    if place(path) == "not shipped":
        lowers.append("test, example or documentation file")
    text = f"{rule} {name}"
    if CREDENTIAL_CODE.search(text):
        pass  # the value is in the code: the service's exposure and importance do not limit who has it
    elif REACH_NEEDED.search(text) and not NO_ATTACKER_NEEDED.search(text):
        _service(ctx, lowers)
    elif ctx.criticality == "low":
        lowers.append("low business criticality")
    return decide(start, base, raises, lowers)


def secret(kind: str, paths: list[str] | str, client_key: bool = False, ctx: Context = Context(),
           names: list[str] = ()) -> Priority:
    """A secret (one kind in one file). The service's exposure does not matter: everyone who can
    read the repository, its clones and its CI logs has the value. `names` are the scanner's
    redacted matches, which carry the variable name but not the value."""
    paths = [paths] if isinstance(paths, str) else list(paths)
    generic = not client_key and bool(GENERIC_SECRET.search(kind or ""))
    if client_key:
        start, base = 2, "client key that ships in the app (restrict it)"
    elif generic:
        start, base = 1, "generic key or token"
    else:
        start, base = 0, "working credential by its format"
    raises, lowers = [], []
    if generic and any(SIGNING_OR_PASSWORD_NAME.search(n or "") for n in names):
        raises.append("named as a signing key or password")
    if not client_key and any(place(p) == "served" for p in paths):
        raises.append("in a file served to browsers")
    if ctx.visibility == "public":
        raises.append("public repository")
    if paths and all(place(p) == "not shipped" for p in paths):
        lowers.append("test, example or documentation file")
    return decide(start, base, raises, lowers)


def dependency(severity: str, reachable: str, manifest: str, ctx: Context = Context()) -> Priority:
    """A vulnerable package: its worst advisory, then reachability and the service."""
    start, base = _severity(severity)
    lowers = []
    if reachable == "No":
        lowers.append("not imported by the code")
    if place(manifest) == "not shipped":
        lowers.append("manifest of a test or example")
    _service(ctx, lowers)
    return decide(start, base, [], lowers)


def configuration(severity: str, path: str, ctx: Context = Context()) -> Priority:
    """A configuration check (Dockerfile, Kubernetes, Terraform). Most of them limit the damage
    after a break-in, so the service's exposure does not lower them."""
    start, base = _severity(severity)
    lowers = []
    if place(path) == "not shipped":
        lowers.append("test, example or documentation file")
    if ctx.criticality == "low":
        lowers.append("low business criticality")
    return decide(start, base, [], lowers)


# ----------------------------------------------------------------------- inventory
INVENTORY_COLUMNS = ("repository", "exposure", "criticality", "visibility", "note")


def load_inventory(path: Path, warn=lambda message: print(message, file=sys.stderr)) -> dict[str, dict]:
    """repository (lower case) -> {exposure, criticality, visibility, note} from a tab-separated file.

    The first non-comment line names the columns; `repository` is required, the others are
    optional. A value outside its list is reported and left out, so it counts as not recorded:
    a typo never lowers a priority.
    """
    inventory, header = {}, None
    allowed = {"exposure": EXPOSURES, "criticality": CRITICALITIES, "visibility": VISIBILITIES}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        cells = [c.strip() for c in raw.split("\t")]
        if header is None:
            header = [c.lower() for c in cells]
            if "repository" not in header:
                raise ValueError(f"{path}: the first line must name the columns, starting with 'repository'")
            continue
        row = dict(zip(header, cells))
        name = row.get("repository", "").lower()
        if not name:
            continue
        entry = {}
        for column, values in allowed.items():
            value = row.get(column, "").lower()
            if value and value not in values:
                warn(f"{path}:{number}: {column} '{value}' is not one of {', '.join(values)}; ignored")
            elif value:
                entry[column] = value
        entry["note"] = row.get("note", "")
        inventory[name] = entry
    return inventory


def lookup(inventory: dict[str, dict], repository: str) -> dict:
    """The inventory entry for 'workspace/slug' or for the slug alone."""
    key = (repository or "").strip("/").lower()
    return inventory.get(key) or inventory.get(key.rsplit("/", 1)[-1]) or {}


def context(inventory: dict[str, dict] | None, repository: str, exposure: str = "", criticality: str = "",
            visibility: str = "") -> Context:
    """The facts for one repository: explicit values first, then the inventory, then 'not recorded'."""
    entry = lookup(inventory or {}, repository)
    sources = []
    if exposure or criticality or visibility:
        sources.append("command line")
    if entry:
        sources.append("inventory")
    return Context(exposure or entry.get("exposure") or "unknown",
                   criticality or entry.get("criticality") or "normal",
                   visibility or entry.get("visibility") or "private",
                   " and ".join(sources))


def rules_text(ctx: Context) -> list[str]:
    """The rules as the report states them, for this repository's facts."""
    exposure = EXPOSURE_TEXT.get(ctx.exposure, ctx.exposure)
    if ctx.exposure == "unknown":
        facts = ("Service exposure is not recorded for this repository, so every priority assumes the service is "
                 "reachable from the internet.")
    else:
        facts = f"Service exposure: {exposure}; business criticality: {ctx.criticality}" + \
                (f" (from the {ctx.source})" if ctx.source else "") + "."
    return [
        facts,
        "Each finding starts from its severity (Critical P1, High P2, Medium P3, Low P4) and moves one step for "
        "each fact below. The reasons are listed with it (↑ raised, ↓ lowered).",
        "Code: raised when the review judged it real. Lowered when it sits in a test, example or documentation file. "
        "Rules that need an attacker's input (injection, cross-site scripting, server-side request forgery, path "
        "traversal, deserialisation, debug and development servers) are lowered for an internal service. Hard-coded credentials, cryptography, "
        "certificate checks and cross-site request forgery are not: they work without reaching the service directly.",
        "Secrets: a credential recognisable by its format (private key, cloud or service token, password in a URL) "
        "starts at P1, a generic key or token at P2, a client key that ships in the app at P3. Raised when its name "
        "says it signs sessions or is a password (a JWT secret, a salt, SECRET_KEY, a password), when the file is "
        "served to browsers or the repository is public; lowered in test, example or documentation files. The "
        "service's exposure does not count: everyone who can read the repository has the value.",
        "Dependencies: lowered when no scanned source file imports the package, when the manifest belongs to a test "
        "or an example, and for an internal service.",
        "Configuration checks: lowered in test, example or documentation files.",
        "High business criticality cancels the internal-service step; low criticality lowers code (except hard-coded "
        "credentials), dependencies and configuration one step.",
        "Context lowers a finding by at most two steps; a fact that is not known never lowers it. An internal service "
        "is still reachable by anyone on that network and by any compromised service in it.",
        "P1: " + MEANING["P1"] + ". P2: " + MEANING["P2"] + ". P3: " + MEANING["P3"] + ". P4: " + MEANING["P4"] + ".",
    ]
