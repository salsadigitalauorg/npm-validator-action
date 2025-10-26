"""Repository and manifest discovery utilities."""

from __future__ import annotations

from pathlib import Path


EXCLUDES = {"node_modules", ".git", ".venv"}


def discover_manifests(root: Path) -> list[Path]:
    """Find dependency manifests recursively under root (excluding vendor dirs).

    Targets include: package.json, package-lock.json, pnpm-lock.yaml, yarn.lock
    """
    root = root.resolve()
    targets = {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    }
    found: list[Path] = []

    def should_skip(p: Path) -> bool:
        parts = set(p.parts)
        return any(ex in parts for ex in EXCLUDES)

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name not in targets:
            continue
        if should_skip(path.relative_to(root)):
            continue
        found.append(path)

    return found
