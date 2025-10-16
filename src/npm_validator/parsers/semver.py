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
    if len(tokens) > 1:
        ok = True
        for t in tokens:
            if t.startswith(">="):
                ok = ok and (v >= _parse_version(t[2:]))
            elif t.startswith(">"):
                ok = ok and (v > _parse_version(t[1:]))
            elif t.startswith("<="):
                ok = ok and (v <= _parse_version(t[2:]))
            elif t.startswith("<"):
                ok = ok and (v < _parse_version(t[1:]))
            elif t.startswith("=="):
                ok = ok and (v == _parse_version(t[2:]))
            elif t.startswith("="):
                ok = ok and (v == _parse_version(t[1:]))
            else:
                # treat as exact fallback
                ok = ok and (v == _parse_version(t))
        return ok

    # exact version fallback
    try:
        return v == _parse_version(expr)
    except Exception:
        return False
