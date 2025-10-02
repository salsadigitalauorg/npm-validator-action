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

    for proj in projects:
        path = proj.get("path", "")
        for f in proj.get("findings", []):
            pkg = f.get("package", "")
            inst = f.get("installed", "")
            comp = ",".join(f.get("compromised", []) or [])
            lines.append(f"| {path} | {pkg} | {inst} | {comp} |")

    return "\n".join(lines) + "\n"
