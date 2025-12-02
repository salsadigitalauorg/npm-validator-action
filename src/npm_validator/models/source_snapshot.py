"""Source snapshot model for compromised list updates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256


@dataclass(frozen=True)
class SourceSnapshot:
    """Capture the origin metadata for a compromised package list run."""

    retrieved_at: datetime
    url: str
    content_hash: str
    run_id: str

    def __post_init__(self) -> None:
        if self.retrieved_at.tzinfo is None:
            raise ValueError("retrieved_at must be timezone-aware")
        if not self.url:
            raise ValueError("url must be provided")
        if not self.content_hash or len(self.content_hash) != 64:
            raise ValueError("content_hash must be a SHA-256 hex digest")
        if not self.run_id:
            raise ValueError("run_id must be provided")

    def to_dict(self) -> dict[str, str]:
        return {
            "retrievedAt": self.retrieved_at.isoformat().replace("+00:00", "Z"),
            "url": self.url,
            "contentHash": self.content_hash,
            "runId": self.run_id,
        }

    @classmethod
    def from_content(
        cls,
        *,
        url: str,
        content: bytes,
        run_id: str,
        retrieved_at: datetime | None = None,
    ) -> SourceSnapshot:
        timestamp = retrieved_at or datetime.now(timezone.utc)
        digest = sha256(content).hexdigest()
        return cls(retrieved_at=timestamp, url=url, content_hash=digest, run_id=run_id)
