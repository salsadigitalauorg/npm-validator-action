"""Normalised feed representation and registry for multi-feed ingestion.

This module defines a canonical `NormalisedFeedAggregation` type that all upstream
feeds are converted into before downstream processing. The registry maps feed IDs
to their fetch and parse functions, enabling config-driven feed processing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeAlias
from collections.abc import Callable

from .safedep_feed import (
    SafeDepFeedAggregation,
    SafeDepFeedError,
    aggregate_safedep_payload,
    fetch_safedep_feed,
)
from .wiz_feed import (
    WizFeedAggregation,
    WizFeedError,
    aggregate_wiz_payload,
    fetch_wiz_feed,
)


class FeedError(RuntimeError):
    """Base error for failures while fetching or parsing a feed."""


class FeedFetchError(FeedError):
    """Raised when a feed cannot be fetched."""


class FeedParseError(FeedError):
    """Raised when a feed cannot be parsed into an aggregation."""


@dataclass(slots=True)
class NormalisedFeedAggregation:
    """Canonical representation of aggregated feed content.

    All upstream feeds are converted into this shape before downstream processing,
    ensuring the rest of the pipeline is feed-agnostic.
    """

    feed_id: str
    display_name: str
    packages: dict[str, list[str]]
    total_records: int
    skipped_records: list[str]
    raw_payload: bytes

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return bool(self.packages)

    @property
    def package_count(self) -> int:
        """Return the number of unique packages."""
        return len(self.packages)

    @property
    def version_count(self) -> int:
        """Return the total number of package-version pairs."""
        return sum(len(versions) for versions in self.packages.values())


class AggregationProtocol(Protocol):
    """Structural protocol for aggregated feed data."""

    packages: dict[str, list[str]]
    total_records: int
    skipped_records: list[str]


# Type aliases for feed functions
FetchFunction: TypeAlias = Callable[[str], bytes]
ParseFunction: TypeAlias = Callable[[bytes], AggregationProtocol]


@dataclass(slots=True, frozen=True)
class FeedHandler:
    """Handler binding a handler ID to its fetch/parse functions and metadata."""

    feed_id: str
    display_name: str
    fetch: FetchFunction
    parse: ParseFunction


def _wrap_safedep_fetch(url: str) -> bytes:
    """Wrap SafeDep fetch to raise a structured FeedFetchError."""
    try:
        return fetch_safedep_feed(url)
    except SafeDepFeedError as exc:
        raise FeedFetchError(str(exc)) from exc


def _wrap_safedep_parse(payload: bytes) -> SafeDepFeedAggregation:
    """Wrap SafeDep parse to raise a structured FeedParseError."""
    try:
        return aggregate_safedep_payload(payload)
    except SafeDepFeedError as exc:
        raise FeedParseError(str(exc)) from exc


def _wrap_wiz_fetch(url: str) -> bytes:
    """Wrap Wiz fetch to raise a structured FeedFetchError."""
    try:
        return fetch_wiz_feed(url)
    except WizFeedError as exc:
        raise FeedFetchError(str(exc)) from exc


def _wrap_wiz_parse(payload: bytes) -> WizFeedAggregation:
    """Wrap Wiz parse to raise a structured FeedParseError."""
    try:
        return aggregate_wiz_payload(payload)
    except WizFeedError as exc:
        raise FeedParseError(str(exc)) from exc


# Registry of known feed handlers, keyed by handler ID.
# Add new handler types here by defining their fetch/parse wrappers and registering them.
FEED_HANDLERS: dict[str, FeedHandler] = {
    "safedep": FeedHandler(
        feed_id="safedep",
        display_name="SafeDep feed",
        fetch=_wrap_safedep_fetch,
        parse=_wrap_safedep_parse,
    ),
    "wiz": FeedHandler(
        feed_id="wiz",
        display_name="Wiz IOC feed",
        fetch=_wrap_wiz_fetch,
        parse=_wrap_wiz_parse,
    ),
}


class UnknownFeedError(ValueError):
    """Raised when a handler ID is not found in the registry."""


def get_feed_handler(handler_id: str) -> FeedHandler:
    """Return the handler for the given handler ID, or raise UnknownFeedError."""
    handler = FEED_HANDLERS.get(handler_id)
    if handler is None:
        known = ", ".join(sorted(FEED_HANDLERS.keys()))
        raise UnknownFeedError(f"Unknown feed ID '{handler_id}'. Known feeds: {known}")
    return handler


def process_feed(feed_id: str, handler_id: str, url: str) -> NormalisedFeedAggregation:
    """Fetch and parse a feed, returning a normalised aggregation.

    Args:
        feed_id: The configured feed identifier (used for status/metrics).
        handler_id: The handler identifier (must be registered in FEED_HANDLERS).
        url: The URL to fetch the feed from.

    Returns:
        A NormalisedFeedAggregation containing the canonical representation.

    Raises:
        UnknownFeedError: If the handler_id is not registered.
        FeedError: If fetching or parsing fails.
    """
    handler = get_feed_handler(handler_id)
    raw_payload = handler.fetch(url)
    aggregation = handler.parse(raw_payload)

    return NormalisedFeedAggregation(
        feed_id=feed_id,
        display_name=handler.display_name,
        packages=aggregation.packages,
        total_records=aggregation.total_records,
        skipped_records=aggregation.skipped_records,
        raw_payload=raw_payload,
    )


def get_known_feed_ids() -> list[str]:
    """Return a sorted list of all registered handler IDs."""
    return sorted(FEED_HANDLERS.keys())
