#!/usr/bin/env python3
"""Group vulnerable dependencies into concrete upgrade actions (PLAN D7).

Instead of listing dozens of individual CVEs or transitive libraries one by one in
Fix First, packages that move together are grouped into one upgrade action:

  * Maven (`pom.xml` under `src_root` with a Spring Boot parent or BOM import):
    packages in `SPRING_BOOT_MANAGED_GROUPS` become one Spring Boot upgrade action;
    unmanaged Maven packages stay one action each.
  * Lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, etc., when
    present under `src_root`): one lockfile update action per manifest.
  * Everything else (or when the manifest file is missing or unparsable): one
    action per package.

Priority starts from the action's most urgent package priority (sdt_priority.dependency)
and is capped at P2 unless a CVE on the CISA Known Exploited Vulnerabilities (KEV)
catalog affects an imported package (`reachable != "No"`).

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
# parent / BOM. Keeping this list short avoids sweeping in third-party libraries
# that a service pins independently; anything outside it stays its own action.
SPRING_BOOT_MANAGED_GROUPS: tuple[str, ...] = (
    "org.springframework",
    "org.apache.tomcat",
    "com.fasterxml.jackson",
    "io.netty",
    "ch.qos.logback",
    "org.apache.logging.log4j",
    "org.hibernate",
    "org.yaml",
    "org.eclipse.jetty",
    "io.undertow",
    "org.slf4j",
    "com.zaxxer",
    "org.flywaydb",
    "org.liquibase",
)

# Lockfile names that refresh together in one action when present under src_root.
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
    """The lowest version that fixes every advisory of this package, or '' when unknown."""
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
    return _PROP_REF.sub(lambda m: props.get(m.group(1), m.group(0)), value)


def _read_spring_boot_pom(pom_path: Path, src_root: Path, depth: int = 0) -> tuple[str, str] | None:
    """Inspect a Maven pom.xml for a Spring Boot parent or BOM import.

    Returns (kind, version) where kind is 'Spring Boot' or 'Spring Cloud', or None
    when the POM does not declare one or cannot be parsed. Follows local parent
    relativePath up to depth 3 within src_root.
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

    parent_rel = ""
    parent_el = next((c for c in root_el if _tag(c) == "parent"), None)
    if parent_el is not None:
        pg = _resolve_props(_child_text(parent_el, "groupId"), props)
        pa = _resolve_props(_child_text(parent_el, "artifactId"), props)
        pv = _resolve_props(_child_text(parent_el, "version"), props)
        if pv:
            props.setdefault("project.parent.version", pv)
        if pg == "org.springframework.boot" and pa == "spring-boot-starter-parent":
            return ("Spring Boot", pv)
        parent_rel = _child_text(parent_el, "relativePath")
        if parent_rel == "":
            # Only follow implicit ../pom.xml when relativePath tag was omitted (not empty <relativePath/>).
            has_rel_tag = any(_tag(c) == "relativePath" for c in parent_el)
            if not has_rel_tag:
                parent_rel = "../pom.xml"

    spring_cloud: tuple[str, str] | None = None
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
                if dg == "org.springframework.boot" and da == "spring-boot-dependencies":
                    return ("Spring Boot", dv)
                if dg == "org.springframework.cloud" and da == "spring-cloud-dependencies":
                    spring_cloud = ("Spring Cloud", dv)

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
                    return inherited
        except OSError:
            pass

    return spring_cloud


def _is_spring_managed(package: str, kind: str) -> bool:
    if ":" not in (package or ""):
        return False
    group = package.split(":", 1)[0].strip().lower()
    if kind == "Spring Cloud":
        return group == "org.springframework.cloud" or group.startswith("org.springframework.cloud.")
    return any(group == prefix or group.startswith(prefix + ".") for prefix in SPRING_BOOT_MANAGED_GROUPS)


def _single_package_title(row, target: str) -> str:
    pkg = row.package or "(see advisory)"
    if target:
        return f"Upgrade {pkg} ({row.installed} -> {target})" if row.installed else f"Upgrade {pkg} (-> {target})"
    return f"Review {pkg} {row.installed} (no fixed version)".strip()


def _action_priority(packages: list, kev_set: set[str],
                     ctx: sdt_priority.Context) -> tuple[sdt_priority.Priority, tuple[str, ...]]:
    """Compute an UpgradeAction's priority and KEV hits.

    Starts from the most urgent package priority, capped at P2; P1 is allowed
    only when a KEV CVE hits an imported package (reachable != 'No').
    """
    for r in packages:
        if r.priority is None:
            r.priority = sdt_priority.dependency(r.severity, r.reachable, r.manifest, ctx)

    all_kev = sorted({
        cid.upper()
        for r in packages
        for cid in (r.advisories or {})
        if cid.upper() in kev_set
    })
    imported_kev = sorted({
        cid.upper()
        for r in packages
        if getattr(r, "reachable", "Unknown") != "No"
        for cid in (r.advisories or {})
        if cid.upper() in kev_set
    })

    best_row = min(
        packages,
        key=lambda r: (r.priority.rank, SEVERITY_ORDER.index(r.severity), r.package, r.installed),
    )
    best = best_row.priority

    if imported_kev:
        kev_note = f"on the known-exploited list: {', '.join(imported_kev[:3])}"
        if len(imported_kev) > 3:
            kev_note += f" (+{len(imported_kev) - 3})"
        shipped = any(sdt_priority.place(r.manifest) != "not shipped" for r in packages
                      if getattr(r, "reachable", "Unknown") != "No"
                      and any(cid.upper() in kev_set for cid in (r.advisories or {})))
        target_level = "P1" if shipped else sdt_priority.LEVELS[max(0, best.rank - 1)]
        prio = sdt_priority.Priority(
            target_level,
            best.base,
            best.steps + (sdt_priority.Step(kev_note, -1),),
        )
        return prio, tuple(all_kev)

    if best.rank == 0:
        prio = sdt_priority.Priority(
            "P2",
            best.base,
            best.steps + (sdt_priority.Step("capped at P2: no known-exploited advisory", +1),),
        )
        return prio, tuple(all_kev)

    return best, tuple(all_kev)


def _build_action(title: str, manifest: str, packages: list, effort: str,
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
        effort=effort,
        kev=kev_hits,
        priority=priority,
    )


def _single_action(row, kev_set: set[str], ctx: sdt_priority.Context) -> UpgradeAction:
    target = upgrade_to(row)
    effort = "Migration" if _is_major_jump(row.installed, target) else "Drop-in"
    return _build_action(_single_package_title(row, target), row.manifest or "", [row], effort, kev_set, ctx)


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
        manifest_file = _confined_file(src_root, manifest)
        if manifest_file is None:
            actions.extend(_single_action(r, kev_set, context) for r in manifest_rows)
            continue

        lower_name = manifest_file.name.lower()
        if lower_name == "pom.xml":
            spring = _read_spring_boot_pom(manifest_file, Path(src_root))
            if spring is None:
                actions.extend(_single_action(r, kev_set, context) for r in manifest_rows)
                continue
            kind, ver = spring
            managed = [r for r in manifest_rows if _is_spring_managed(r.package, kind)]
            unmanaged = [r for r in manifest_rows if not _is_spring_managed(r.package, kind)]
            if managed:
                title = f"Upgrade {kind} (currently {ver})" if ver else f"Upgrade {kind}"
                major_parent = (kind == "Spring Boot" and bool(_version(ver)) and _version(ver)[0] < 3)
                major_pkg = any(_is_major_jump(r.installed, upgrade_to(r)) for r in managed)
                effort = "Migration" if (major_parent or major_pkg) else "Drop-in"
                actions.append(_build_action(title, manifest, managed, effort, kev_set, context))
            actions.extend(_single_action(r, kev_set, context) for r in unmanaged)
            continue

        lock_label = LOCKFILE_LABELS.get(lower_name)
        if lock_label:
            title = f"{lock_label} ({manifest})"
            effort = "Migration" if any(_is_major_jump(r.installed, upgrade_to(r)) for r in manifest_rows) else "Drop-in"
            actions.append(_build_action(title, manifest, manifest_rows, effort, kev_set, context))
            continue

        actions.extend(_single_action(r, kev_set, context) for r in manifest_rows)

    actions.sort(key=lambda a: (
        a.priority.rank if a.priority else len(sdt_priority.LEVELS),
        SEVERITY_ORDER.index(a.severity),
        -len(a.packages),
        a.manifest,
        a.title,
    ))
    return actions
