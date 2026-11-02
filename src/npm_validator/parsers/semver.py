"""Compare npm versions against the supported subset of SemVer ranges.

Supported expressions are exact versions, caret ranges, tilde ranges and
space-separated comparator sets. Prereleases are included conservatively:
if their SemVer precedence falls inside a range, they match that range.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Any


_VERSION = re.compile(
    r"^[vV]?(0|[1-9][0-9]*)"
    r"(?:\.(0|[1-9][0-9]*))?"
    r"(?:\.(0|[1-9][0-9]*))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


@total_ordering
@dataclass(frozen=True)
class _Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple[tuple[int, int | str], ...] | None = None

    def _key(self) -> tuple[Any, ...]:
        # A normal release sorts after every prerelease of the same version.
        prerelease_key = (1,) if self.prerelease is None else (0, self.prerelease)
        return self.major, self.minor, self.patch, prerelease_key

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _Version):
            return NotImplemented
        return self._key() < other._key()


def _parse_version(raw: str) -> _Version:
    version = raw.strip()
    # npm's semver implementation limits versions to 256 characters.
    match = _VERSION.fullmatch(version) if len(version) <= 256 else None
    if match is None:
        raise ValueError(f"Unsupported or invalid npm version: {raw[:256]!r}")

    prerelease = None
    if match.group(4):
        parts: list[tuple[int, int | str]] = []
        for identifier in match.group(4).split("."):
            if identifier.isdigit():
                if len(identifier) > 1 and identifier.startswith("0"):
                    raise ValueError(f"Invalid numeric prerelease identifier: {raw[:256]!r}")
                # Numeric identifiers have lower precedence than non-numeric ones.
                parts.append((0, int(identifier)))
            else:
                parts.append((1, identifier))
        prerelease = tuple(parts)

    return _Version(
        major=int(match.group(1)),
        minor=int(match.group(2) or 0),
        patch=int(match.group(3) or 0),
        prerelease=prerelease,
    )


def _next_major(version: _Version) -> _Version:
    return _Version(version.major + 1, 0, 0)


def _next_minor(version: _Version) -> _Version:
    return _Version(version.major, version.minor + 1, 0)


def _satisfies_token(version: _Version, token: str) -> bool:
    if token.startswith(">="):
        return version >= _parse_version(token[2:])
    if token.startswith(">"):
        return version > _parse_version(token[1:])
    if token.startswith("<="):
        return version <= _parse_version(token[2:])
    if token.startswith("<"):
        return version < _parse_version(token[1:])
    if token.startswith("=="):
        return version == _parse_version(token[2:])
    if token.startswith("="):
        return version == _parse_version(token[1:])
    return version == _parse_version(token)


def satisfies(installed: str, expr: str) -> bool:
    """Return whether a version matches, raising ValueError for unsupported input."""
    version = _parse_version(installed)
    expr = expr.strip()

    if expr.startswith("^"):
        base = _parse_version(expr[1:])
        return base <= version < _next_major(base)

    if expr.startswith("~"):
        base = _parse_version(expr[1:])
        return base <= version < _next_minor(base)

    tokens = expr.split()
    if tokens and any(token[:1] in {"<", ">", "="} for token in tokens):
        # Parse every comparator even when an earlier one did not match, so an
        # unsupported part of a range cannot silently produce a clean result.
        return all([_satisfies_token(version, token) for token in tokens])

    return version == _parse_version(expr)
