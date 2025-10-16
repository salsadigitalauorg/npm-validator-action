"""Parse package.json and extract dependencies across sections."""

from __future__ import annotations

from pathlib import Path


def parse(path: Path) -> list[tuple[str, str]]:
    """Return list of (package, version_expr) from all dependency sections.

    Sections: dependencies, devDependencies, peerDependencies, optionalDependencies.
    """
    import json

    data: dict[str, dict[str, str]] = json.loads(path.read_text(encoding="utf-8"))
    sections = (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    )
    pairs: list[tuple[str, str]] = []
    for section in sections:
        deps = data.get(section) or {}
        for name, version in deps.items():
            pairs.append((name, str(version)))

    return pairs
