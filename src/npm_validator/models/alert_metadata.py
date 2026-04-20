"""Alert metadata model for compromised list updater."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable

_VALID_SEVERITIES = {"info", "warn", "critical"}


@dataclass(frozen=True)
class AlertMetadata:
    """Structured alert payload emitted when the updater fails."""

    severity: str
    message: str
    channels_notified: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")
        if not self.message:
            raise ValueError("Alert message must be non-empty")
        if not self.channels_notified:
            raise ValueError("At least one channel must be provided")
        if any(not channel for channel in self.channels_notified):
            raise ValueError("Channels must be non-empty strings")

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity,
            "message": self.message,
            "channelsNotified": list(self.channels_notified),
        }

    @classmethod
    def from_iterable(
        cls, *, severity: str, message: str, channels: Iterable[str]
    ) -> AlertMetadata:
        return cls(severity=severity, message=message, channels_notified=tuple(channels))
