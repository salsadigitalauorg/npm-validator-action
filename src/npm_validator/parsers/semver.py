"""Minimal semver range handling built atop packaging.version.

Supported expressions:
- exact versions (e.g., "1.2.3")
- caret ranges ^x.y.z → >=x.y.z,<x+1.0.0
- tilde ranges ~x.y.z → >=x.y.z,<x.y+1.0
- basic comparator sets split by spaces, e.g., ">=1.0.0 <2.0.0"
"""

from __future__ import annotations


from packaging.version import Version


def _parse_version(v: str) -> Version:
    return Version(v)


def _next_major(v: Version) -> Version:
    return Version(f"{v.major + 1}.0.0")


def _next_minor(v: Version) -> Version:
    return Version(f"{v.major}.{v.minor + 1}.0")


def _satisfies_token(version: Version, token: str) -> bool:
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
    v = _parse_version(installed)
    expr = expr.strip()

    # caret ^x.y.z
    if expr.startswith("^"):
        base = _parse_version(expr[1:])
        lower = base
        upper = _next_major(base)
        return (v >= lower) and (v < upper)

    # tilde ~x.y.z
    if expr.startswith("~"):
        base = _parse_version(expr[1:])
        lower = base
        upper = _next_minor(base)
        return (v >= lower) and (v < upper)

    # composite comparators like ">=1.0.0 <2.0.0" (space separated)
    tokens: list[str] = expr.split()
    if tokens and any(token[:1] in {"<", ">", "="} for token in tokens):
        return all(_satisfies_token(v, token) for token in tokens)

    # exact version fallback
    try:
        return v == _parse_version(expr)
    except Exception:
        return False
