"""Parse npm package-lock.json to capture resolved transitive dependencies."""

from __future__ import annotations

from pathlib import Path


def parse(path: Path) -> list[tuple[str, str]]:
    """Return list of (package, version) from lockfile.

    Supports npm v1 ("dependencies" tree) and v2+ ("packages" map).
    """
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    pairs: list[tuple[str, str]] = []

    # npm v2+ format
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            if key.startswith("node_modules/"):
                name = key.split("/", 1)[1]
                version = meta.get("version")
                if version:
                    pairs.append((name, str(version)))

    # npm v1 format fallback
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            if isinstance(meta, dict) and "version" in meta:
                pairs.append((name, str(meta["version"])))

    return pairs
