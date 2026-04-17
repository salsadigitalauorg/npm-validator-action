"""SafeDep feed ingestion helpers."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from collections.abc import Iterable

import requests
from requests import Response
from tenacity import retry, stop_after_attempt, wait_fixed

SAFEDEP_FEED_URL = (
    "https://raw.githubusercontent.com/safedep/"
    "shai-hulud-migration-response/main/data/ioc/malicious-package-versions.jsonl"
)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


class SafeDepFeedError(RuntimeError):
    """Raised when the SafeDep feed cannot be fetched or parsed."""


@dataclass(slots=True)
class SafeDepFeedAggregation:
    """Aggregated SafeDep feed content."""

    packages: dict[str, list[str]]
    total_records: int
    skipped_records: list[str]

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return bool(self.packages)


@retry(reraise=True, stop=stop_after_attempt(3), wait=wait_fixed(2))
def _http_get(url: str) -> Response:
    return requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)


def fetch_safedep_feed(url: str = SAFEDEP_FEED_URL) -> bytes:
    """Return the raw SafeDep JSONL payload."""

    try:
        response = _http_get(url)
    except requests.RequestException as exc:  # pragma: no cover - network failure path
        raise SafeDepFeedError(f"Failed to fetch SafeDep feed: {exc}") from exc

    if response.status_code != 200:
        raise SafeDepFeedError(
            f"Unexpected status code {response.status_code} fetching SafeDep feed"
        )

    return response.content


def _iter_lines(payload: bytes) -> Iterable[str]:
    for raw_line in payload.splitlines():
        line = raw_line.decode("utf-8", errors="replace").strip()
        if line:
            yield line


def aggregate_safedep_payload(payload: bytes) -> SafeDepFeedAggregation:
    """Aggregate SafeDep JSONL payload into mapping of package -> versions."""

    packages: dict[str, set[str]] = defaultdict(set)
    skipped: list[str] = []
    total = 0

    for index, line in enumerate(_iter_lines(payload), start=1):
        total += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            skipped.append(f"line {index}: invalid JSON ({exc.msg})")
            continue

        name = str(record.get("name", "")).strip()
        version = str(record.get("version", "")).strip()

        if not name or not version:
            skipped.append(f"line {index}: missing name or version")
            continue

        packages[name].add(version)

    if not packages:
        raise SafeDepFeedError("SafeDep feed returned no valid package entries")

    sorted_packages = {name: sorted(versions) for name, versions in packages.items()}
    return SafeDepFeedAggregation(
        packages=sorted_packages,
        total_records=total,
        skipped_records=skipped,
    )
