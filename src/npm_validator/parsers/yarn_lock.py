"""Parse yarn.lock to capture resolved dependencies."""

from __future__ import annotations

from pathlib import Path


def parse(path: Path) -> list[tuple[str, str]]:
    """Return list of (package, version) from yarn lock file."""
    lines = path.read_text(encoding="utf-8").splitlines()
    pairs: list[tuple[str, str]] = []

    current_name: str | None = None
    for raw in lines:
        line = raw.rstrip()
        if not line:
            current_name = None
            continue
        if not line.startswith(" ") and line.endswith(":"):
            header = line[:-1]
            first = header.split(",", 1)[0]
            if first.startswith("@"):
                try:
                    idx = first.index("@", 1)
                    current_name = first[:idx]
                except ValueError:
                    current_name = first
            else:
                current_name = first.split("@", 1)[0]
            continue

        if current_name and line.strip().startswith("version "):
            part = line.strip().split(" ", 1)[1].strip()
            if part.startswith('"') and part.endswith('"'):
                version = part.strip('"')
            else:
                version = part
            pairs.append((current_name, version))

    return pairs
