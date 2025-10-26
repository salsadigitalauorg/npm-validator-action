"""Snapshot representation for compromised package lists."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable, Mapping

from .alert_metadata import AlertMetadata
from .package_entry import PackageEntry
from .source_snapshot import SourceSnapshot

_VALID_STATUSES = {"updated", "no-change", "failed"}


@dataclass(frozen=True)
class ChangeSummary:
    """Describe changes detected between two snapshots."""

    added: int
    removed: int
    status: str

    def __post_init__(self) -> None:
        if self.added < 0 or self.removed < 0:
            raise ValueError("Change counts must be non-negative")
        if self.status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {self.status}")

    def to_dict(self) -> dict[str, object]:
        return {
            "added": self.added,
            "removed": self.removed,
            "status": self.status,
        }

    @classmethod
    def from_counts(cls, *, added: int, removed: int) -> ChangeSummary:
        status = "no-change" if added == 0 and removed == 0 else "updated"
        return cls(added=added, removed=removed, status=status)


@dataclass(frozen=True)
class CompromisedListSnapshot:
    """Immutable representation of the compromised package snapshot."""

    source: SourceSnapshot
    packages: tuple[PackageEntry, ...]
    change_summary: ChangeSummary | None = None
    alert_metadata: AlertMetadata | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "source": self.source.to_dict(),
            "packages": [entry.to_dict() for entry in self.packages],
            "totals": self.totals,
        }
        if self.change_summary is not None:
            data["changeSummary"] = self.change_summary.to_dict()
        if self.alert_metadata is not None:
            data["alertMetadata"] = self.alert_metadata.to_dict()
        return data

    @property
    def totals(self) -> dict[str, int]:
        package_count = len(self.packages)
        version_count = sum(len(entry.versions) for entry in self.packages)
        return {"packages": package_count, "versions": version_count}

    @classmethod
    def from_entries(
        cls,
        *,
        source: SourceSnapshot,
        entries: Iterable[PackageEntry],
        change_summary: ChangeSummary | None = None,
        alert_metadata: AlertMetadata | None = None,
    ) -> CompromisedListSnapshot:
        normalized = tuple(sorted(entries, key=lambda entry: entry.name))
        return cls(
            source=source,
            packages=normalized,
            change_summary=change_summary,
            alert_metadata=alert_metadata,
        )

    @classmethod
    def from_mapping(
        cls,
        *,
        source: SourceSnapshot,
        mapping: Mapping[str, Iterable[str]],
        change_summary: ChangeSummary | None = None,
        alert_metadata: AlertMetadata | None = None,
    ) -> CompromisedListSnapshot:
        entries = [PackageEntry.from_iterable(name, versions) for name, versions in mapping.items()]
        return cls.from_entries(
            source=source,
            entries=entries,
            change_summary=change_summary,
            alert_metadata=alert_metadata,
        )

    def packages_by_name(self) -> dict[str, PackageEntry]:
        return {entry.name: entry for entry in self.packages}

    def diff(self, previous: CompromisedListSnapshot) -> ChangeSummary:
        current_names = {entry.name for entry in self.packages}
        previous_names = {entry.name for entry in previous.packages}
        added = len(current_names - previous_names)
        removed = len(previous_names - current_names)
        return ChangeSummary.from_counts(added=added, removed=removed)
