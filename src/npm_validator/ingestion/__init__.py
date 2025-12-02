"""Utilities for fetching and aggregating external threat intelligence feeds."""

from .safedep_feed import (
    SAFEDEP_FEED_URL,
    SafeDepFeedAggregation,
    SafeDepFeedError,
    fetch_safedep_feed,
    aggregate_safedep_payload,
)
from .wiz_feed import (
    WIZ_FEED_URL,
    WizFeedAggregation,
    WizFeedError,
    fetch_wiz_feed,
    aggregate_wiz_payload,
)
from .normalised_feed import (
    FeedError,
    FeedFetchError,
    FeedHandler,
    FeedParseError,
    NormalisedFeedAggregation,
    UnknownFeedError,
    FEED_HANDLERS,
    get_feed_handler,
    get_known_feed_ids,
    process_feed,
)
from .feeds_config import (
    ConfigError,
    FeedConfig,
    Settings,
    load_settings,
    validate_feed_ids,
)

__all__ = [
    # SafeDep feed
    "SAFEDEP_FEED_URL",
    "SafeDepFeedAggregation",
    "SafeDepFeedError",
    "fetch_safedep_feed",
    "aggregate_safedep_payload",
    # Wiz feed
    "WIZ_FEED_URL",
    "WizFeedAggregation",
    "WizFeedError",
    "fetch_wiz_feed",
    "aggregate_wiz_payload",
    # Normalised feed abstraction
    "FeedError",
    "FeedFetchError",
    "FeedHandler",
    "FeedParseError",
    "NormalisedFeedAggregation",
    "UnknownFeedError",
    "FEED_HANDLERS",
    "get_feed_handler",
    "get_known_feed_ids",
    "process_feed",
    # Configuration
    "ConfigError",
    "FeedConfig",
    "Settings",
    "load_settings",
    "validate_feed_ids",
]
