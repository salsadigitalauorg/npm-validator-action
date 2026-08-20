"""Parse pnpm-lock.yaml to capture resolved dependencies."""

from __future__ import annotations

from pathlib import Path


def parse(path: Path) -> list[tuple[str, str]]:
    """Return list of (package, version) from pnpm lock file."""
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    pkgs = data.get("packages") or {}

    pairs: list[tuple[str, str]] = []
    for key in pkgs.keys():
        # Keys look like "/name@1.2.3" or "/@scope/name@1.2.3"
        if not isinstance(key, str) or not key.startswith("/"):
            continue
        ref = key[1:]
        if "@" not in ref:
            continue
        name, version = ref.rsplit("@", 1)
        pairs.append((name, version))

    return pairs
