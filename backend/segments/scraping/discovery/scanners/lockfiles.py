"""Lock file parsing for the dependency graph.

A manifest says what a project *declares*. Only a lock file says what it
actually *resolved to* and, crucially, which package pulled in which. That
parent/child structure is the difference between "the app depends on
cryptography" and "the app depends on requests, which depends on
cryptography" -- and the second is what a migration has to reason about.

Supported lock formats (all resolved with stdlib parsers):

    package-lock.json   npm, pnpm, yarn (v1 tree + v2/v3 package map)
    composer.lock       PHP
    Cargo.lock          Rust
    poetry.lock         Python
    Pipfile.lock        Python (flat: no parent edges)

Formats without parent information produce nodes but no edges, which is
recorded honestly rather than guessed at.
"""

from __future__ import annotations

import json
import re

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


LOCK_FILES = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "composer.lock": "composer",
    "Cargo.lock": "cargo",
    "poetry.lock": "poetry",
    "Pipfile.lock": "pypi",
    "Gemfile.lock": "bundler",
    "pnpm-lock.yaml": "npm",
    "yarn.lock": "npm",
    "packages.lock.json": "nuget",
    "Podfile.lock": "cocoapods",
}


def ecosystem_for_lockfile(filename: str) -> str:
    return LOCK_FILES.get(filename, "")


def _version(raw: str | None) -> str:
    if not raw:
        return ""
    return re.sub(r"^[\^~>=<\s]+", "", str(raw)).strip()


# --- npm ---------------------------------------------------------------------

def parse_package_lock(text: str) -> dict:
    """npm lock files. Returns {"packages": [...], "edges": [(parent, child)]}.

    v2/v3 keep a flat "packages" map keyed by path (``node_modules/a/node_modules/b``)
    where the parent is derivable from the path. v1 nests a "dependencies" tree
    directly, which is the same information in a different shape.
    """
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {"packages": [], "edges": [], "direct": []}

    packages: list[dict] = []
    edges: list[tuple[str, str]] = []
    direct: list[str] = []

    raw_packages = data.get("packages")
    if isinstance(raw_packages, dict):
        root = raw_packages.get("") or {}
        declared = set()
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            block = root.get(field)
            if isinstance(block, dict):
                declared.update(block)

        for path, meta in raw_packages.items():
            if not path or not isinstance(meta, dict):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            if not name:
                continue
            packages.append(
                {
                    "package": name,
                    "version": _version(meta.get("version")),
                    "ecosystem": "npm",
                    "dev": bool(meta.get("dev")),
                }
            )
            if name in declared:
                direct.append(name)

            # `node_modules/a/node_modules/b` means b is nested under a.
            if "node_modules/" in path:
                # Slice at the last separator and strip the separator's own
                # trailing slash: rsplit consumes the separator and leaves
                # "node_modules/a/", which misses the parent lookup and makes
                # the derived parent name "a/" instead of "a".
                parent_path = path[: path.rfind("node_modules/")].rstrip("/")
                parent = raw_packages.get(parent_path, {})
                parent_name = parent.get("name") if isinstance(parent, dict) else None
                parent_name = parent_name or parent_path.rsplit("node_modules/", 1)[-1]
                if parent_name and parent_name != name:
                    edges.append((parent_name, name))
        return {"packages": packages, "edges": edges, "direct": direct}

    # lockfileVersion 1: nested tree.
    def walk(node: dict, parent: str | None) -> None:
        for name, meta in (node or {}).items():
            if not isinstance(meta, dict):
                continue
            packages.append(
                {
                    "package": name,
                    "version": _version(meta.get("version")),
                    "ecosystem": "npm",
                    "dev": bool(meta.get("dev")),
                }
            )
            if parent:
                edges.append((parent, name))
            walk(meta.get("dependencies") or {}, name)

    walk(data.get("dependencies") or {}, None)
    return {"packages": packages, "edges": edges, "direct": []}


# --- composer ----------------------------------------------------------------

def parse_composer_lock(text: str) -> dict:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {"packages": [], "edges": [], "direct": []}

    packages: list[dict] = []
    edges: list[tuple[str, str]] = []
    direct: list[str] = []

    for block, dev in (("packages", False), ("packages-dev", True)):
        for entry in data.get(block) or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            if not name:
                continue
            packages.append(
                {
                    "package": name,
                    "version": _version(entry.get("version")),
                    "ecosystem": "composer",
                    "dev": dev,
                }
            )
            if dev:
                continue
            for parent in entry.get("require") or {}:
                if isinstance(parent, str) and parent != "php":
                    edges.append((name, parent))
            if entry.get("type") == "metapackage":
                continue

    for entry in data.get("packages-dev") or []:
        if isinstance(entry, dict) and entry.get("name"):
            direct.append(entry["name"])
    return {"packages": packages, "edges": edges, "direct": direct}


# --- cargo -------------------------------------------------------------------

def parse_cargo_lock(text: str) -> dict:
    if tomllib is None:
        return {"packages": [], "edges": [], "direct": []}
    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return {"packages": [], "edges": [], "direct": []}

    packages: list[dict] = []
    edges: list[tuple[str, str]] = []
    for entry in data.get("package") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        if not name:
            continue
        packages.append(
            {
                "package": name,
                "version": _version(entry.get("version")),
                "ecosystem": "cargo",
                "dev": False,
            }
        )
        for child in entry.get("dependencies") or []:
            if isinstance(child, str) and child != name:
                edges.append((name, child))
    return {"packages": packages, "edges": edges, "direct": []}


# --- poetry ------------------------------------------------------------------

def parse_poetry_lock(text: str) -> dict:
    if tomllib is None:
        return {"packages": [], "edges": [], "direct": []}
    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return {"packages": [], "edges": [], "direct": []}

    packages: list[dict] = []
    edges: list[tuple[str, str]] = []
    for entry in data.get("package") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        if not name:
            continue
        packages.append(
            {
                "package": name,
                "version": _version(entry.get("version")),
                "ecosystem": "pypi",
                "dev": entry.get("category") == "dev",
            }
        )
        children = entry.get("dependencies")
        if isinstance(children, dict):
            for child in children:
                if isinstance(child, str) and child.lower() != name.lower():
                    edges.append((name, child))
    return {"packages": packages, "edges": edges, "direct": []}


# --- flat lock files (nodes, no edges) ---------------------------------------

def parse_pipfile_lock(text: str) -> dict:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {"packages": [], "edges": [], "direct": [], "flat": True}
    packages: list[dict] = []
    for block, dev in (("default", False), ("develop", True)):
        entries = data.get(block)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            version = ""
            if isinstance(spec, dict):
                version = _version(str(spec.get("version", "")))
            packages.append(
                {"package": name, "version": version, "ecosystem": "pypi", "dev": dev}
            )
    return {"packages": packages, "edges": [], "direct": [], "flat": True}


def parse_gemfile_lock(text: str) -> dict:
    """Gemfile.lock: specs carry their own child list, which is real edge data."""
    packages: list[dict] = []
    edges: list[tuple[str, str]] = []
    current: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        spec = re.match(r"^([A-Za-z0-9._-]+)\s+\(([^)]+)\)$", stripped)
        if spec and indent == 4:
            current = spec.group(1)
            packages.append(
                {
                    "package": current,
                    "version": _version(spec.group(2).split()[0]),
                    "ecosystem": "bundler",
                    "dev": False,
                }
            )
            continue
        if current and indent >= 6 and stripped and not stripped.startswith("!"):
            edges.append((current, stripped.split()[0]))
    return {"packages": packages, "edges": edges, "direct": []}


_PARSERS = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "composer.lock": parse_composer_lock,
    "Cargo.lock": parse_cargo_lock,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "Gemfile.lock": parse_gemfile_lock,
}


def parse_lockfile(filename: str, text: str) -> dict:
    """Parse a lock file. Unknown files yield an empty result."""
    parser = _PARSERS.get(filename)
    if parser is None:
        return {"packages": [], "edges": [], "direct": []}
    return parser(text)
