"""Configuration loader for multi-feed ingestion.

Reads feed configuration from a JSON file (default: settings.json) and validates
the structure. Each feed entry must have an ``id`` and ``url``; optional fields
include ``enabled`` (default True), ``description``, and ``handler``.

The JSON Schema in ``settings.schema.json`` is provided for tooling/editor
support. This module performs its own lightweight validation at runtime rather
than invoking a full JSON Schema validator.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .normalised_feed import get_known_feed_ids


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[3] / "settings.json"
CONFIG_PATH_ENV_VAR = "NPM_VALIDATOR_FEEDS_CONFIG"


class ConfigError(RuntimeError):
    """Raised when the configuration file cannot be loaded or is invalid."""


@dataclass(slots=True, frozen=True)
class FeedConfig:
    """Configuration for a single feed."""

    id: str
    url: str
    enabled: bool
    description: str
    handler: str

    @classmethod
    def from_dict(cls, data: dict[str, Any], index: int) -> FeedConfig:
        """Create a FeedConfig from a dictionary, validating required fields."""
        feed_id = data.get("id")
        if not feed_id or not isinstance(feed_id, str):
            raise ConfigError(f"Feed at index {index} is missing required 'id' field")

        url = data.get("url")
        if not url or not isinstance(url, str):
            raise ConfigError(f"Feed '{feed_id}' is missing required 'url' field")

        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"Feed '{feed_id}' has invalid 'enabled' field (must be boolean)")

        description = data.get("description", "")
        if not isinstance(description, str):
            raise ConfigError(f"Feed '{feed_id}' has invalid 'description' field (must be string)")

        handler = data.get("handler", feed_id)
        if not isinstance(handler, str) or not handler:
            raise ConfigError(
                f"Feed '{feed_id}' has invalid 'handler' field (must be non-empty string)"
            )

        return cls(
            id=feed_id,
            url=url,
            enabled=enabled,
            description=description,
            handler=handler,
        )


@dataclass(slots=True, frozen=True)
class Settings:
    """Top-level settings container."""

    feeds: list[FeedConfig]

    def get_enabled_feeds(self) -> list[FeedConfig]:
        """Return only the feeds that are enabled."""
        return [feed for feed in self.feeds if feed.enabled]

    def get_feed_by_id(self, feed_id: str) -> FeedConfig | None:
        """Return the feed config with the given ID, or None if not found."""
        for feed in self.feeds:
            if feed.id == feed_id:
                return feed
        return None


def _resolve_config_path(path: Path | str | None = None) -> Path:
    """Resolve the configuration file path.

    Priority:
    1. Explicit path argument
    2. NPM_VALIDATOR_FEEDS_CONFIG environment variable
    3. Default path (settings.json in repo root)
    """
    if path is not None:
        return Path(path)

    env_path = os.environ.get(CONFIG_PATH_ENV_VAR)
    if env_path:
        return Path(env_path)

    return DEFAULT_CONFIG_PATH


def load_settings(path: Path | str | None = None) -> Settings:
    """Load and validate settings from a JSON file.

    Args:
        path: Optional path to the config file. If not provided, uses the
            NPM_VALIDATOR_FEEDS_CONFIG env var or falls back to settings.json.

    Returns:
        A Settings object containing validated feed configurations.

    Raises:
        ConfigError: If the file cannot be read or contains invalid data.
    """
    config_path = _resolve_config_path(path)

    if not config_path.exists():
        raise ConfigError(f"Configuration file not found: {config_path}")

    try:
        content = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Failed to read configuration file: {exc}") from exc

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in configuration file: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Configuration must be a JSON object")

    feeds_data = data.get("feeds")
    if feeds_data is None:
        raise ConfigError("Configuration is missing required 'feeds' array")

    if not isinstance(feeds_data, list):
        raise ConfigError("'feeds' must be an array")

    if not feeds_data:
        raise ConfigError("'feeds' array must contain at least one entry")

    feeds: list[FeedConfig] = []
    seen_ids: set[str] = set()

    for index, feed_data in enumerate(feeds_data):
        if not isinstance(feed_data, dict):
            raise ConfigError(f"Feed at index {index} must be an object")

        feed_config = FeedConfig.from_dict(feed_data, index)

        if feed_config.id in seen_ids:
            raise ConfigError(f"Duplicate feed ID: '{feed_config.id}'")
        seen_ids.add(feed_config.id)

        feeds.append(feed_config)

    return Settings(feeds=feeds)


def validate_feed_ids(settings: Settings) -> None:
    """Validate that all enabled feed IDs have registered handlers.

    Raises:
        ConfigError: If any enabled feed ID is not registered.
    """
    known_handler_ids = set(get_known_feed_ids())
    enabled_feeds = settings.get_enabled_feeds()

    unknown_handlers = [
        feed.handler for feed in enabled_feeds if feed.handler not in known_handler_ids
    ]
    if unknown_handlers:
        known_list = ", ".join(sorted(known_handler_ids))
        unknown_list = ", ".join(sorted(unknown_handlers))
        raise ConfigError(
            f"Unknown feed handler(s): {unknown_list}. " f"Registered handlers: {known_list}"
        )
