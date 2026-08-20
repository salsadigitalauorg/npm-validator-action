"""Wiz Research IOC feed ingestion helpers."""

from __future__ import annotations

import csv
import io
import re
from collections import defaultdict
from dataclasses import dataclass
from collections.abc import Iterable

import requests
from requests import Response
from tenacity import retry, stop_after_attempt, wait_fixed

WIZ_FEED_URL = (
    "https://raw.githubusercontent.com/wiz-sec-public/"
    "wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"
)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


class WizFeedError(RuntimeError):
    """Raised when the Wiz IOC feed cannot be fetched or parsed."""


@dataclass(slots=True)
class WizFeedAggregation:
    """Aggregated Wiz IOC feed content."""

    packages: dict[str, list[str]]
    total_records: int
    skipped_records: list[str]

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return bool(self.packages)


@retry(reraise=True, stop=stop_after_attempt(3), wait=wait_fixed(2))
def _http_get(url: str) -> Response:
    return requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)


def fetch_wiz_feed(url: str = WIZ_FEED_URL) -> bytes:
    """Return the raw Wiz IOC CSV payload."""

    try:
        response = _http_get(url)
    except requests.RequestException as exc:  # pragma: no cover - network failure path
        raise WizFeedError(f"Failed to fetch Wiz feed: {exc}") from exc

    if response.status_code != 200:
        raise WizFeedError(f"Unexpected status code {response.status_code} fetching Wiz feed")

    return response.content


_VERSION_PATTERN = re.compile(r"^[0-9A-Za-z.+-]+$")


def _normalize_versions(raw: str) -> list[str]:
    versions: list[str] = []
    for candidate in raw.split("||"):
        cleaned = candidate.strip()
        cleaned = re.sub(r"^[=<>~^\s]+", "", cleaned)
        cleaned = cleaned.lstrip("v")
        if not cleaned:
            continue
        if not _VERSION_PATTERN.fullmatch(cleaned):
            raise ValueError(f"invalid version '{candidate.strip()}'")
        versions.append(cleaned)
    return versions


def _iter_rows(payload: bytes) -> Iterable[dict[str, str]]:
    text = payload.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise WizFeedError("Wiz feed payload is missing headers")
    required_headers = {"Package", "Version"}
    if not required_headers.issubset(set(reader.fieldnames)):
        raise WizFeedError("Wiz feed missing required headers: Package, Version")
    yield from reader


def aggregate_wiz_payload(payload: bytes) -> WizFeedAggregation:
    """Aggregate Wiz CSV payload into mapping of package -> versions."""

    packages: dict[str, set[str]] = defaultdict(set)
    skipped: list[str] = []
    total = 0

    for index, row in enumerate(_iter_rows(payload), start=2):
        total += 1
        name = (row.get("Package") or "").strip()
        version_field = (row.get("Version") or "").strip()

        if not name or not version_field:
            skipped.append(f"row {index}: missing package or version")
            continue

        try:
            versions = _normalize_versions(version_field)
        except ValueError as exc:
            skipped.append(f"row {index}: {exc}")
            continue

        if not versions:
            skipped.append(f"row {index}: no versions after normalization")
            continue

        for version in versions:
            packages[name].add(version)

    if not packages:
        raise WizFeedError("Wiz feed returned no valid package entries")

    sorted_packages = {name: sorted(versions) for name, versions in packages.items()}
    return WizFeedAggregation(
        packages=sorted_packages,
        total_records=total,
        skipped_records=skipped,
    )
