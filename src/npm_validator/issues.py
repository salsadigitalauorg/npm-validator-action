"""Optional GitHub Issue creation/update logic.

This module should use the GITHUB_TOKEN when running in Actions, but it must not
be a hard dependency in the core scan flow. Import lazily in the wrapper when
enabled.
"""

from __future__ import annotations

from typing import Any


ISSUE_TITLE = "Security findings detected by npm-validator"
LEGACY_ISSUE_TITLE = "Compromised npm packages detected by npm-validator"
ISSUE_LABELS = ["security", "dependencies", "npm-validator"]
ISSUE_MARKER = "<!-- npm-validator-issue-marker: do-not-edit -->"


def _pick_issue_to_update(issues: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Choose an existing issue to update based on marker or title match."""
    for it in issues:
        body = it.get("body") or ""
        if ISSUE_MARKER in body:
            return it
    # Fallback by title
    for it in issues:
        if it.get("title") in {ISSUE_TITLE, LEGACY_ISSUE_TITLE}:
            return it
    return None


def _build_issue_body(report: dict[str, Any]) -> str:
    lines = [ISSUE_MARKER]
    packages = []
    for proj in report.get("projects", []):
        path = proj.get("path", "")
        for f in proj.get("findings", []):
            packages.append(
                f"- {path}: {f.get('package')} {f.get('installed')} (listed versions: {','.join(f.get('compromised', []) or [])})"
            )
    if packages:
        lines.extend(["", "Detected listed npm package versions:", "", *packages])

    runtime_checks = [
        check
        for check in report.get("runtimeChecks", [])
        if check.get("status") == "potentially_affected"
    ]
    if runtime_checks:
        lines.extend(["", "Potentially affected Node.js versions (CVE-2026-111497):", ""])
        for check in runtime_checks:
            source = _single_line(check.get("source", ""))
            version = _single_line(check.get("version", ""))
            guidance = _single_line(check.get("guidance", ""))
            lines.append(f"- {source}: {version}. {guidance}")
    return "\n".join(lines) + "\n"


def _single_line(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", " ")


def create_or_update_issue(
    report: dict[str, Any],
    token: str,
    repository: str,
    labels: list[str] | None = None,
) -> str:
    """Create or update a single issue; return issue URL.

    Minimal implementation for local tests: performs simple GET/POST/PATCH
    against GitHub REST API. For tests, this should be monkeypatched to avoid
    network. Raises on HTTP errors.
    """
    import requests

    owner_repo = repository
    api = f"https://api.github.com/repos/{owner_repo}/issues"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}

    # Find existing issues
    r = requests.get(api, params={"state": "open", "per_page": 50}, headers=headers, timeout=10)
    r.raise_for_status()
    existing = r.json()
    chosen = _pick_issue_to_update(existing if isinstance(existing, list) else [])

    title = ISSUE_TITLE
    body = _build_issue_body(report)
    labels = labels or ISSUE_LABELS

    if chosen:
        issue_url = chosen.get("url")
        r2 = requests.patch(
            issue_url,
            json={"title": title, "body": body, "labels": labels},
            headers=headers,
            timeout=10,
        )
        r2.raise_for_status()
        return r2.json().get("html_url", "")
    else:
        r2 = requests.post(
            api, json={"title": title, "body": body, "labels": labels}, headers=headers, timeout=10
        )
        r2.raise_for_status()
        return r2.json().get("html_url", "")
