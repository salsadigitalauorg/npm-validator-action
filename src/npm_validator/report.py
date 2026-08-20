"""Report aggregation and schema-friendly output."""

from __future__ import annotations

from typing import Any


def finding_has_complete_patch_evidence(finding: dict[str, Any]) -> bool:
    """Return True when every npm lockfile instance has patch-package evidence."""

    instances = {
        str(instance)
        for instance in finding.get("packageLockInstances", [])
        if isinstance(instance, str) and instance
    }
    if not instances:
        return False

    patched_instances = {
        str(patch.get("packageLockInstance"))
        for patch in finding.get("patches", [])
        if isinstance(patch, dict) and patch.get("packageLockInstance")
    }
    return instances.issubset(patched_instances)


def count_blocking_findings(report: dict[str, Any]) -> int:
    """Count findings that still need remediation before CI can pass."""

    blocking = 0
    for project in report.get("projects", []):
        if not isinstance(project, dict):
            continue
        findings = project.get("findings", [])
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict) or not finding_has_complete_patch_evidence(finding):
                blocking += 1
    return blocking


def aggregate(projects: list[dict[str, Any]], scan_context: str = "repo") -> dict[str, Any]:
    """Aggregate per-project findings into a single schema-compatible report.

    The input ``projects`` is expected to be a list of dicts with at least
    ``path`` and ``findings`` keys. ``findings`` is a list of objects containing
    ``package``, ``installed`` and ``compromised`` (list of versions).

    This function does minimal aggregation needed for schema conformance:
    computes totals and top-level flags, and passes projects through.
    """

    total_projects = len(projects)
    total_findings = sum(len(p.get("findings", [])) for p in projects)
    total_blocking_findings = count_blocking_findings({"projects": projects})

    report: dict[str, Any] = {
        "version": "1",  # schema requires a string; semantic managed by callers
        "hasFindings": total_findings > 0,
        "blockingFindings": total_blocking_findings,
        "scanContext": scan_context,
        "projects": projects,
        "totals": {
            "projects": total_projects,
            "findings": total_findings,
        },
    }

    return report
