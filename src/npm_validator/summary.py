"""Human-readable summary rendering for $GITHUB_STEP_SUMMARY."""

from __future__ import annotations

from typing import Any


def render_summary(report: dict[str, Any], validator_version: str | None = None) -> str:
    """Return a Markdown string with totals and a table of vulnerable packages."""
    totals = report.get("totals", {})
    projects = report.get("projects", [])

    lines = []
    lines.append("# npm-validator Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Total projects | {totals.get('projects', 0)} |")
    lines.append(f"| Findings | {totals.get('findings', 0)} |")
    if validator_version:
        lines.append(f"| Validator release tag | v{validator_version} |")
    lines.append("")
    lines.append(
        "| Project | Package | Installed | Dependency Type | Dependency Path | Listed Versions |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- |")

    has_rows = False

    for proj in projects:
        path = proj.get("path") or "(unknown project)"
        findings = proj.get("findings") or []
        if not findings:
            lines.append(f"| {path} | No listed packages | n/a | n/a | n/a | n/a |")
            has_rows = True
            continue

        for finding in findings:
            pkg = finding.get("package", "")
            inst = finding.get("installed", "")
            dep_type = finding.get("dependencyType", "unknown")
            dep_path = " > ".join(finding.get("dependencyPath", []) or []) or "n/a"
            comp = ",".join(finding.get("compromised", []) or [])
            lines.append(f"| {path} | {pkg} | {inst} | {dep_type} | {dep_path} | {comp} |")
            has_rows = True

    if not has_rows:
        lines.append("| (no projects scanned) | No listed packages | n/a | n/a | n/a | n/a |")

    runtime_checks = report.get("runtimeChecks") or []
    if runtime_checks:
        lines.extend(
            [
                "",
                "## Node.js Brotli checks (CVE-2026-111497)",
                "",
                (
                    "Version declarations do not prove which runtime is deployed. "
                    "Vendor backports may affect the result."
                ),
                "",
                "| Source | Version | Status | Guidance |",
                "| --- | --- | --- | --- |",
            ]
        )
        for check in runtime_checks:
            source = _table_cell(check.get("source", ""))
            version = _table_cell(check.get("version", ""))
            status = _runtime_status(check.get("status", "unknown"))
            guidance = _table_cell(check.get("guidance", ""))
            lines.append(f"| {source} | {version} | {status} | {guidance} |")

    return "\n".join(lines) + "\n"


def _table_cell(value: Any) -> str:
    value = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    value = value.replace("[", "&#91;").replace("]", "&#93;").replace("`", "&#96;")
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _runtime_status(status: str) -> str:
    return {
        "potentially_affected": "Potentially affected",
        "not_affected": "Not affected by the upstream version range",
        "unknown": "Inconclusive",
    }.get(status, "Inconclusive")
