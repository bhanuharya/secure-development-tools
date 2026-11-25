#!/usr/bin/env python3
"""Group vulnerable dependencies into concrete upgrade actions (PLAN D7).

Instead of listing dozens of individual CVEs or transitive libraries one by one in
Fix First, packages that move together are grouped into one upgrade action:

  * Maven (`pom.xml` under `src_root` with a Spring Boot or JHipster parent/BOM):
    packages in `SPRING_BOOT_MANAGED_GROUPS` become one upgrade action; unmanaged
    Maven packages stay one action each. Missing or unparsable `pom.xml` falls
    back to one action per package.
  * Lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, etc.): one
    lockfile update action per manifest (no file under `src_root` required).
  * Other non-archive manifests (`go.mod`, `requirements.txt`, `build.gradle`,
    `pubspec.yaml`, etc.): one action per manifest, titled "Update N packages in
    <manifest>" (no file under `src_root` required).
  * Java archives (`.jar`, `.war`, `.ear`) and findings without a manifest: one
    action per package.

Effort is "Migration" when any package target's major version is above its
installed major version, else "Drop-in".

Priority uses `sdt_priority.dependency()` for every package, and an action takes
its most urgent package's priority (so a package table row never ranks above its
action).

Standard library only.
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

_TOOLS_DIR = str(Path(__file__).resolve().parent)
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)
import sdt_priority  # noqa: E402

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")
OPEN_STATES = ("To review", "Open", "Not reviewed", "Confirmed")

# Deliberately short list of Maven groupId prefixes managed by the Spring Boot
# parent / BOM (and BOMs that import spring-boot-dependencies, such as JHipster).
# Keeping this list short avoids sweeping in third-party libraries that a service
# pins independently; anything outside it stays its own action.
SPRING_BOOT_MANAGED_GROUPS: tuple[str, ...] = (
    "org.springframework",
    "org.apache.tomcat",
    "com.fasterxml.jackson",
    "io.netty",
    "ch.qos.logback",
    "org.apache.logging.log4j",
    "org.hibernate",
    "org.yaml",
    "org.thymeleaf",
    "io.micrometer",
    "com.hazelcast",
    "org.eclipse.jetty",
    "io.undertow",
    "org.slf4j",
    "com.zaxxer",
    "org.flywaydb",
    "org.liquibase",
)

# Parent POMs and imported BOMs that manage the Spring Boot dependency set.
SPRING_BOOT_BOMS: dict[tuple[str, str], str] = {
    ("org.springframework.boot", "spring-boot-starter-parent"): "Spring Boot",
    ("org.springframework.boot", "spring-boot-dependencies"): "Spring Boot",
    ("tech.jhipster", "jhipster-dependencies"): "JHipster",
    ("io.github.jhipster", "jhipster-dependencies"): "JHipster",
}

# Lockfile names that refresh together in one action per manifest.
LOCKFILE_LABELS: dict[str, str] = {
    "package-lock.json": "Update npm lockfile",
    "npm-shrinkwrap.json": "Update npm lockfile",
    "yarn.lock": "Update Yarn lockfile",
    "pnpm-lock.yaml": "Update pnpm lockfile",
    "poetry.lock": "Update Poetry lockfile",
    "pipfile.lock": "Update Pipenv lockfile",
    "uv.lock": "Update uv lockfile",
    "pubspec.lock": "Update pubspec lockfile",
    "cargo.lock": "Update Cargo lockfile",
    "gemfile.lock": "Update Bundler lockfile",
    "composer.lock": "Update Composer lockfile",
}

JAVA_ARCHIVE_SUFFIXES = (".jar", ".war", ".ear")

_PROP_REF = re.compile(r"\$\{([^}]+)\}")


@dataclass
class UpgradeAction:
    """One concrete dependency upgrade covering one or more vulnerable packages."""
    title: str
    manifest: str
    packages: list = field(default_factory=list)
    targets: dict[str, str] = field(default_factory=dict)  # package -> upgrade_to() target
    counts: dict[str, int] = field(default_factory=dict)   # severity -> package count
    effort: str = "Drop-in"  # "Drop-in" | "Migration"
    kev: tuple[str, ...] = ()  # sorted CVE ids found on the KEV catalog
    priority: sdt_priority.Priority | None = None

    @property
    def open(self) -> bool:
        return any(getattr(r, "status", "Open") in OPEN_STATES for r in self.packages)

    @property
    def severity(self) -> str:
        return min((r.severity for r in self.packages), key=SEVERITY_ORDER.index, default="Medium")


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", text or "")[:4])


def upgrade_to(row) -> str:
    """The lowest version that fixes every advisory of this package, or '' when unknown.

    Each advisory lists one fixed version per maintained branch; the useful one is the
    lowest at or above the installed version. The package needs the highest of those.
    """
    installed, targets = _version(getattr(row, "installed", "")), []
    for fixed in (getattr(row, "fixed", None) or {}).values():
        candidates = sorted((_version(v), v.strip()) for v in str(fixed).split(",") if _version(v))
        above = [c for c in candidates if c[0] >= installed] or candidates
        if above:
            targets.append(above[0])
    return max(targets)[1] if targets else ""


def _is_major_jump(installed: str, target: str) -> bool:
    """True when upgrading from installed to target crosses a major version boundary."""
    cur, nxt = _version(installed), _version(target)
    if not cur or not nxt:
        return False
    return nxt[0] > cur[0]


def _action_effort(packages: list) -> str:
    """'Migration' when any package target's major version exceeds its installed major, else 'Drop-in'."""
    return "Migration" if any(_is_major_jump(r.installed, upgrade_to(r)) for r in packages) else "Drop-in"


def load_kev(path: Path | str | None,
             warn=lambda message: print(message, file=sys.stderr)) -> set[str]:
    """Load CVE ids from a local CISA KEV JSON catalog. Never downloads; missing file warns."""
    if not path:
        return set()
    target = Path(path)
    if not target.is_file():
        warn(f"sdt_upgrades: KEV catalog not found ({target}); continuing without KEV list")
        return set()
    try:
        doc = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        warn(f"sdt_upgrades: KEV catalog unreadable ({target}: {exc}); continuing without KEV list")
        return set()
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        warn(f"sdt_upgrades: KEV catalog has no 'vulnerabilities' list ({target}); ignored")
        return set()
    return {
        str(item.get("cveID") or "").strip().upper()
        for item in vulns
        if isinstance(item, dict) and str(item.get("cveID") or "").strip()
    }


def _confined_file(src_root: Path | None, rel: str) -> Path | None:
    """Return resolved path for `rel` inside `src_root`, or None if absent or outside root."""
    if src_root is None or not rel:
        return None
    try:
        root = Path(src_root).resolve()
        candidate = (root / rel).resolve()
    except OSError:
        return None
    if candidate != root and root not in candidate.parents:
        return None
    return candidate if candidate.is_file() else None


def _tag(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1]


def _child_text(el: ET.Element, name: str) -> str:
    for child in el:
        if _tag(child) == name:
            return (child.text or "").strip()
    return ""


def _resolve_props(value: str, props: dict[str, str]) -> str:
    if not value or "${" not in value:
        return value
    resolved = _PROP_REF.sub(lambda m: props.get(m.group(1), m.group(0)), value)
    return "" if "${" in resolved else resolved


def _read_spring_boot_pom(pom_path: Path, src_root: Path, depth: int = 0) -> tuple[str, str, str] | None:
    """Inspect a Maven pom.xml for a Spring Boot / JHipster parent or BOM import.

    Returns (kind, version, spring_boot_version) where kind is 'Spring Boot',
    'JHipster', or 'Spring Cloud', or None when the POM does not declare one or
    cannot be parsed. Follows local parent relativePath up to depth 3 within
    src_root.
    """
    if depth > 3:
        return None
    try:
        root_el = ET.fromstring(pom_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ET.ParseError, ValueError):
        return None
    if _tag(root_el) != "project":
        return None

    props: dict[str, str] = {}
    for child in root_el:
        if _tag(child) == "properties":
            for prop in child:
                val = (prop.text or "").strip()
                if val:
                    props[_tag(prop)] = val
    sb_prop = _resolve_props(props.get("spring-boot.version", ""), props)

    parent_rel = ""
    parent_el = next((c for c in root_el if _tag(c) == "parent"), None)
    if parent_el is not None:
        pg = _resolve_props(_child_text(parent_el, "groupId"), props)
        pa = _resolve_props(_child_text(parent_el, "artifactId"), props)
        pv = _resolve_props(_child_text(parent_el, "version"), props)
        if pv:
            props.setdefault("project.parent.version", pv)
        kind = SPRING_BOOT_BOMS.get((pg, pa))
        if kind:
            return (kind, pv, sb_prop if kind != "Spring Boot" else "")
        parent_rel = _child_text(parent_el, "relativePath")
        if parent_rel == "":
            has_rel_tag = any(_tag(c) == "relativePath" for c in parent_el)
            if not has_rel_tag:
                parent_rel = "../pom.xml"

    spring_cloud: tuple[str, str, str] | None = None
    for child in root_el:
        if _tag(child) != "dependencyManagement":
            continue
        for deps in child:
            if _tag(deps) != "dependencies":
                continue
            for dep in deps:
                if _tag(dep) != "dependency":
                    continue
                scope = _resolve_props(_child_text(dep, "scope"), props).lower()
                dtype = _resolve_props(_child_text(dep, "type"), props).lower()
                if scope != "import" or dtype != "pom":
                    continue
                dg = _resolve_props(_child_text(dep, "groupId"), props)
                da = _resolve_props(_child_text(dep, "artifactId"), props)
                dv = _resolve_props(_child_text(dep, "version"), props)
                kind = SPRING_BOOT_BOMS.get((dg, da))
                if kind:
                    return (kind, dv, sb_prop if kind != "Spring Boot" else "")
                if dg == "org.springframework.cloud" and da == "spring-cloud-dependencies":
                    spring_cloud = ("Spring Cloud", dv, "")

    if parent_rel:
        try:
            parent_candidate = (pom_path.parent / parent_rel).resolve()
            root_resolved = Path(src_root).resolve()
            if parent_candidate.is_dir():
                parent_candidate = parent_candidate / "pom.xml"
            if (parent_candidate == root_resolved or root_resolved in parent_candidate.parents) \
                    and parent_candidate.is_file() and parent_candidate != pom_path:
                inherited = _read_spring_boot_pom(parent_candidate, src_root, depth + 1)
                if inherited is not None:
                    kind, ver, inherited_sb = inherited
                    return (kind, ver, inherited_sb or (sb_prop if kind != "Spring Boot" else ""))
        except OSError:
            pass

    return spring_cloud


def _spring_title(kind: str, ver: str, sb_ver: str) -> str:
    if kind == "JHipster":
        if ver and sb_ver:
            return f"Upgrade JHipster (currently {ver}; Spring Boot {sb_ver})"
        if ver:
            return f"Upgrade JHipster (currently {ver})"
        if sb_ver:
            return f"Upgrade JHipster (Spring Boot {sb_ver})"
        return "Upgrade JHipster"
    return f"Upgrade {kind} (currently {ver})" if ver else f"Upgrade {kind}"


def _is_spring_managed(package: str, kind: str) -> bool:
    if ":" not in (package or ""):
        return False
    group = package.split(":", 1)[0].strip().lower()
    if kind == "Spring Cloud":
        return group == "org.springframework.cloud" or group.startswith("org.springframework.cloud.")
    if kind == "JHipster" and (
        group in ("tech.jhipster", "io.github.jhipster")
        or group.startswith(("tech.jhipster.", "io.github.jhipster."))
    ):
        return True
    return any(group == prefix or group.startswith(prefix + ".") for prefix in SPRING_BOOT_MANAGED_GROUPS)


def _single_package_title(row, target: str) -> str:
    pkg = row.package or "(see advisory)"
    if target:
        return f"Upgrade {pkg} ({row.installed} -> {target})" if row.installed else f"Upgrade {pkg} (-> {target})"
    return f"Review {pkg} {row.installed} (no fixed version)".strip()


def package_kev_hits(row, kev_set: set[str]) -> tuple[str, ...]:
    """Sorted KEV CVE ids on `row` when it is imported (reachable != 'No'), else ()."""
    if not kev_set or getattr(row, "reachable", "Unknown") == "No":
        return ()
    return tuple(sorted(
        cid.upper() for cid in (getattr(row, "advisories", None) or {}) if cid.upper() in kev_set
    ))


def _action_priority(packages: list, kev_set: set[str],
                     ctx: sdt_priority.Context) -> tuple[sdt_priority.Priority, tuple[str, ...]]:
    """Compute package priorities with sdt_priority.dependency() and take the most urgent."""
    for r in packages:
        hits = package_kev_hits(r, kev_set)
        r.priority = sdt_priority.dependency(
            r.severity, r.reachable, r.manifest, ctx,
            known_exploited=bool(hits), kev_ids=hits,
        )

    all_kev = tuple(sorted({
        cid.upper()
        for r in packages
        for cid in (r.advisories or {})
        if cid.upper() in kev_set
    }))
    imported_kev = tuple(sorted({
        cid
        for r in packages
        for cid in package_kev_hits(r, kev_set)
    }))

    best_row = min(
        packages,
        key=lambda r: (
            r.priority.rank,
            not bool(package_kev_hits(r, kev_set)),
            SEVERITY_ORDER.index(r.severity),
            r.package,
            r.installed,
        ),
    )
    best = best_row.priority
    if len(imported_kev) > 1 and best.base.startswith("on the known-exploited list"):
        ids = ", ".join(imported_kev[:3]) + (f" (+{len(imported_kev) - 3})" if len(imported_kev) > 3 else "")
        best = sdt_priority.Priority(best.level, f"on the known-exploited list: {ids}", best.steps, best.impact)
    return best, all_kev


def _build_action(title: str, manifest: str, packages: list,
                  kev_set: set[str], ctx: sdt_priority.Context) -> UpgradeAction:
    targets: dict[str, str] = {}
    for r in packages:
        t = upgrade_to(r)
        key = r.package or "(see advisory)"
        if key not in targets or (_version(t) > _version(targets[key])):
            targets[key] = t
    counts = {sev: sum(1 for r in packages if r.severity == sev) for sev in SEVERITY_ORDER}
    counts = {sev: n for sev, n in counts.items() if n}
    priority, kev_hits = _action_priority(packages, kev_set, ctx)
    ordered_pkgs = sorted(packages, key=lambda r: (r.priority.rank, SEVERITY_ORDER.index(r.severity),
                                                   r.package, r.installed))
    return UpgradeAction(
        title=title,
        manifest=manifest,
        packages=ordered_pkgs,
        targets=targets,
        counts=counts,
        effort=_action_effort(packages),
        kev=kev_hits,
        priority=priority,
    )


def _single_action(row, kev_set: set[str], ctx: sdt_priority.Context) -> UpgradeAction:
    target = upgrade_to(row)
    return _build_action(_single_package_title(row, target), row.manifest or "", [row], kev_set, ctx)


def group_upgrades(rows: list, src_root: Path | None = None, kev: Iterable[str] = (),
                   ctx: sdt_priority.Context | None = None) -> list[UpgradeAction]:
    """Group DependencyRows into UpgradeActions ordered most urgent first."""
    if not rows:
        return []
    context = ctx or sdt_priority.Context()
    kev_set = {str(c).strip().upper() for c in (kev or ()) if str(c).strip()}

    by_manifest: "OrderedDict[str, list]" = OrderedDict()
    for r in rows:
        by_manifest.setdefault(r.manifest or "", []).append(r)

    actions: list[UpgradeAction] = []
    for manifest, manifest_rows in by_manifest.items():
        lower_name = Path(manifest).name.lower() if manifest else ""

        # No manifest or Java archive (.jar, .war, .ear): stay one action per package.
        if not manifest or lower_name.endswith(JAVA_ARCHIVE_SUFFIXES):
            actions.extend(_single_action(r, kev_set, context) for r in manifest_rows)
            continue

        # Maven pom.xml: only rule that inspects a file under src_root.
        if lower_name == "pom.xml":
            manifest_file = _confined_file(src_root, manifest)
            spring = _read_spring_boot_pom(manifest_file, Path(src_root)) if manifest_file is not None else None
            if spring is None:
                actions.extend(_single_action(r, kev_set, context) for r in manifest_rows)
                continue
            kind, ver, sb_ver = spring
            managed = [r for r in manifest_rows if _is_spring_managed(r.package, kind)]
            unmanaged = [r for r in manifest_rows if not _is_spring_managed(r.package, kind)]
            if managed:
                actions.append(_build_action(_spring_title(kind, ver, sb_ver), manifest, managed, kev_set, context))
            actions.extend(_single_action(r, kev_set, context) for r in unmanaged)
            continue

        # Lockfiles: one lockfile update action per manifest (no file under src_root needed).
        lock_label = LOCKFILE_LABELS.get(lower_name)
        if lock_label:
            actions.append(_build_action(f"{lock_label} ({manifest})", manifest, manifest_rows, kev_set, context))
            continue

        # Other ecosystems (go.mod, requirements.txt, build.gradle, pubspec.yaml, etc.):
        # one action per manifest, titled "Update N packages in <manifest>".
        n = len(manifest_rows)
        title = f"Update {n} {'package' if n == 1 else 'packages'} in {manifest}"
        actions.append(_build_action(title, manifest, manifest_rows, kev_set, context))

    actions.sort(key=lambda a: (
        a.priority.rank if a.priority else len(sdt_priority.LEVELS),
        SEVERITY_ORDER.index(a.severity),
        -len(a.packages),
        a.manifest,
        a.title,
    ))
    return actions
