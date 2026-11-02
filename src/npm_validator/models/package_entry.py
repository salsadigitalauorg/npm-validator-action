"""Package entry model."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable


@dataclass(frozen=True)
class PackageEntry:
    """Represent a compromised package and its affected versions."""

    name: str
    versions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Package name must be non-empty")
        if not self.versions:
            raise ValueError("Package must contain at least one version")
        if any(not version for version in self.versions):
            raise ValueError("Versions must be non-empty strings")
        if list(self.versions) != sorted(self.versions):
            raise ValueError("Versions must be sorted lexicographically")
        if len(set(self.versions)) != len(self.versions):
            raise ValueError("Versions must be unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "versions": list(self.versions),
        }

    @classmethod
    def from_iterable(cls, name: str, versions: Iterable[str]) -> PackageEntry:
        unique = sorted({version for version in versions})
        return cls(name=name, versions=tuple(unique))
