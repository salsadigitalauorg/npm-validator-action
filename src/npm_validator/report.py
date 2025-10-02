"""Report aggregation and schema-friendly output."""

from __future__ import annotations

from typing import Any


def aggregate(projects: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-project findings into a single schema-compatible report.

    The input ``projects`` is expected to be a list of dicts with at least
    ``path`` and ``findings`` keys. ``findings`` is a list of objects containing
    ``package``, ``installed`` and ``compromised`` (list of versions).

    This function does minimal aggregation needed for schema conformance:
    computes totals and top-level flags, and passes projects through.
    """

    total_projects = len(projects)
    total_findings = sum(len(p.get("findings", [])) for p in projects)

    report: dict[str, Any] = {
        "version": "1",  # schema requires a string; semantic managed by callers
        "hasFindings": total_findings > 0,
        "projects": projects,
        "totals": {
            "projects": total_projects,
            "findings": total_findings,
        },
    }

    return report
