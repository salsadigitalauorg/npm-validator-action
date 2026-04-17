"""Custom registry feed ingestion helpers.

Reads a curated JSON file of known-compromised packages maintained in the
repository.  Unlike external feeds, an empty package list is valid (it means
"no custom overrides").
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


class CustomRegistryFeedError(RuntimeError):
    """Raised when the custom registry cannot be read or parsed."""


@dataclass(slots=True)
class CustomRegistryFeedAggregation:
    """Aggregated custom registry content."""

    packages: dict[str, list[str]]
    total_records: int
    skipped_records: list[str]

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return bool(self.packages)


def fetch_custom_registry(path_or_url: str) -> bytes:
    """Read the custom registry file from disk.

    Relative paths are resolved against the repository root.
    """
    file_path = Path(path_or_url)
    if not file_path.is_absolute():
        file_path = REPO_ROOT / file_path

    if not file_path.exists():
        raise CustomRegistryFeedError(f"Custom registry file not found: {file_path}")

    try:
        return file_path.read_bytes()
    except OSError as exc:
        raise CustomRegistryFeedError(f"Failed to read custom registry: {exc}") from exc


def aggregate_custom_registry_payload(
    payload: bytes,
) -> CustomRegistryFeedAggregation:
    """Parse the custom registry JSON payload into a package mapping."""

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise CustomRegistryFeedError(f"Invalid JSON in custom registry: {exc}") from exc

    if not isinstance(data, dict):
        raise CustomRegistryFeedError("Custom registry must be a JSON object")

    packages_list = data.get("packages")
    if packages_list is None:
        raise CustomRegistryFeedError("Custom registry is missing required 'packages' array")

    if not isinstance(packages_list, list):
        raise CustomRegistryFeedError("'packages' must be an array")

    # Empty list is intentional — no custom overrides.
    if not packages_list:
        return CustomRegistryFeedAggregation(
            packages={},
            total_records=0,
            skipped_records=[],
        )

    packages: dict[str, set[str]] = defaultdict(set)
    skipped: list[str] = []
    total = 0

    for index, entry in enumerate(packages_list):
        total += 1

        if not isinstance(entry, dict):
            skipped.append(f"entry {index}: not an object")
            continue

        name = entry.get("name")
        if not name or not isinstance(name, str):
            skipped.append(f"entry {index}: missing or invalid 'name'")
            continue

        versions = entry.get("versions")
        if not isinstance(versions, list):
            skipped.append(f"entry {index} ({name}): missing or invalid 'versions'")
            continue

        valid_count = 0
        for version in versions:
            if isinstance(version, str) and version.strip():
                packages[name].add(version.strip())
                valid_count += 1

        if not valid_count:
            skipped.append(f"entry {index} ({name}): no valid version strings in 'versions'")

    sorted_packages = {name: sorted(versions) for name, versions in packages.items()}
    return CustomRegistryFeedAggregation(
        packages=sorted_packages,
        total_records=total,
        skipped_records=skipped,
    )
