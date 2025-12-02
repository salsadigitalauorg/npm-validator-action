"""Human-readable summary rendering for $GITHUB_STEP_SUMMARY."""

from __future__ import annotations

from typing import Any


def render_summary(report: dict[str, Any]) -> str:
    """Return a Markdown string with totals and a table of vulnerable packages."""
    totals = report.get("totals", {})
    projects = report.get("projects", [])

    lines = []
    lines.append("# npm-validator Summary")
    lines.append("")
    lines.append(
        f"Total projects: {totals.get('projects', 0)} | Findings: {totals.get('findings', 0)}"
    )
    lines.append("")
    lines.append("| Project | Package | Installed | Compromised |")
    lines.append("| --- | --- | --- | --- |")

    has_rows = False

    for proj in projects:
        path = proj.get("path") or "(unknown project)"
        findings = proj.get("findings") or []
        if not findings:
            lines.append(f"| {path} | No compromised packages | n/a | n/a |")
            has_rows = True
            continue

        for finding in findings:
            pkg = finding.get("package", "")
            inst = finding.get("installed", "")
            comp = ",".join(finding.get("compromised", []) or [])
            lines.append(f"| {path} | {pkg} | {inst} | {comp} |")
            has_rows = True

    if not has_rows:
        lines.append("| (no projects scanned) | No compromised packages | n/a | n/a |")

    return "\n".join(lines) + "\n"
