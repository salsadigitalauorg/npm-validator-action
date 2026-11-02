"""Parse npm package-lock.json to capture resolved transitive dependencies."""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def _package_name_from_key(key: str) -> str:
    """Best-effort package name for npm v2+ package keys.

    Examples:
    - ``node_modules/axios`` -> ``axios``
    - ``node_modules/@scope/pkg`` -> ``@scope/pkg``
    - ``node_modules/browser-sync/node_modules/localtunnel`` -> ``localtunnel``
    """

    if not key.startswith("node_modules/"):
        return key

    tail = key.rsplit("node_modules/", 1)[-1].strip("/")
    parts = [part for part in tail.split("/") if part]
    if not parts:
        return tail
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def parse(path: Path) -> list[tuple[str, str]]:
    """Return list of (package, version) from lockfile.

    Supports npm v1 ("dependencies" tree) and v2+ ("packages" map).
    """
    data = _load(path)
    pairs: list[tuple[str, str]] = []

    # npm v2+ format
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            if key.startswith("node_modules/"):
                name = _package_name_from_key(key)
                version = meta.get("version")
                if version:
                    pairs.append((name, str(version)))

    # npm v1 format fallback
    for instance in _inspect_v1(data)["instances"]:
        pairs.append((instance["name"], instance["version"]))

    return pairs


def inspect(path: Path) -> dict[str, Any]:
    """Return dependency metadata derived from a package-lock.json file.

    The result is intentionally lightweight and optimised for triage:
    - root production and development dependency entrypoints
    - unique package instances with version/dev flags
    - shortest dependency chain from root to each package name
    """

    data = _load(path)
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return _inspect_v1(data)

    root_meta = packages.get("")
    if not isinstance(root_meta, dict):
        root_meta = {}

    root_dependencies = set((root_meta.get("dependencies") or {}).keys())
    root_dev_dependencies = set((root_meta.get("devDependencies") or {}).keys())

    name_graph: dict[str, set[str]] = {}
    instances: list[dict[str, Any]] = []

    for key, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        if not key.startswith("node_modules/"):
            continue

        name = meta.get("name")
        if not isinstance(name, str) or not name:
            name = _package_name_from_key(key)

        version = meta.get("version")
        if not version:
            continue

        dependencies = meta.get("dependencies") or {}
        dependency_names = {str(dep_name) for dep_name in dependencies.keys()}

        name_graph.setdefault(name, set()).update(dependency_names)
        instances.append(
            {
                "key": key,
                "name": name,
                "version": str(version),
                "dev": meta.get("dev"),
                "dependencies": sorted(dependency_names),
            }
        )

    return {
        "root_dependencies": root_dependencies,
        "root_dev_dependencies": root_dev_dependencies,
        "instances": instances,
        "name_graph": name_graph,
    }


def _inspect_v1(data: dict[str, Any]) -> dict[str, Any]:
    deps = data.get("dependencies")
    if not isinstance(deps, dict):
        return {
            "root_dependencies": set(),
            "root_dev_dependencies": set(),
            "instances": [],
            "name_graph": {},
        }

    name_graph: dict[str, set[str]] = {}
    instances: list[dict[str, Any]] = []
    root_dependencies = {str(name) for name in deps.keys()}
    root_dev_dependencies: set[str] = set()

    def walk(
        dependencies: dict[str, Any],
        parent_key: str = "",
        inherited_dev: bool | None = None,
    ) -> None:
        for name, meta in dependencies.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not version:
                continue

            package_name = str(name)
            key = (
                f"{parent_key}/node_modules/{package_name}"
                if parent_key
                else f"node_modules/{package_name}"
            )
            dev = meta.get("dev", inherited_dev)
            nested_deps = meta.get("dependencies") or {}
            requires = meta.get("requires") or {}
            dependency_names = {str(dep_name) for dep_name in requires.keys()}
            if isinstance(nested_deps, dict):
                dependency_names.update(str(dep_name) for dep_name in nested_deps.keys())

            name_graph.setdefault(package_name, set()).update(dependency_names)
            instances.append(
                {
                    "key": key,
                    "name": package_name,
                    "version": str(version),
                    "dev": dev,
                    "dependencies": sorted(dependency_names),
                }
            )

            if isinstance(nested_deps, dict):
                walk(
                    nested_deps,
                    parent_key=key,
                    inherited_dev=dev if isinstance(dev, bool) else None,
                )

    walk(deps)

    return {
        "root_dependencies": root_dependencies,
        "root_dev_dependencies": root_dev_dependencies,
        "instances": instances,
        "name_graph": name_graph,
    }


def _shortest_path(
    roots: set[str],
    graph: dict[str, set[str]],
    target: str,
) -> list[str] | None:
    if target in roots:
        return [target]

    queue: deque[list[str]] = deque([[root] for root in sorted(roots)])
    seen = set(roots)

    while queue:
        path = queue.popleft()
        current = path[-1]
        for dep in sorted(graph.get(current, set())):
            if dep == target:
                return [*path, dep]
            if dep in seen:
                continue
            seen.add(dep)
            queue.append([*path, dep])

    return None


def describe_match_from_metadata(
    metadata: dict[str, Any],
    package_name: str,
    version: str,
) -> dict[str, Any]:
    """Return triage metadata for a matched package from inspected metadata."""

    instances = [
        instance
        for instance in metadata["instances"]
        if instance["name"] == package_name and instance["version"] == version
    ]

    dependency_path: list[str] = []
    dependency_type = "unknown"

    production_path = _shortest_path(
        metadata["root_dependencies"],
        metadata["name_graph"],
        package_name,
    )
    development_path = _shortest_path(
        metadata["root_dev_dependencies"],
        metadata["name_graph"],
        package_name,
    )

    if production_path:
        dependency_path = production_path
        dependency_type = "production"
    elif development_path:
        dependency_path = development_path
        dependency_type = "development"
    elif any(instance.get("dev") is True for instance in instances):
        dependency_type = "development"
    elif any(instance.get("dev") is False for instance in instances):
        dependency_type = "production"

    return {
        "dependencyPath": dependency_path,
        "dependencyType": dependency_type,
        "packageLockInstances": [instance["key"] for instance in instances],
    }


def describe_match(path: Path, package_name: str, version: str) -> dict[str, Any]:
    """Return triage metadata for a matched package in a package-lock file."""

    return describe_match_from_metadata(inspect(path), package_name=package_name, version=version)
