"""Helpers for creating GitHub issues when the updater fails."""

from __future__ import annotations

from datetime import date
from typing import Any

import requests

from npm_validator.ingestion import SAFEDEP_FEED_URL

ISSUE_MARKER = "<!-- npm-validator-issue-marker: do-not-edit -->"
ISSUE_LABELS = ["security", "dependencies", "npm-validator"]


def _today() -> date:
    return date.today()


def _select_issue(issues: list[dict[str, Any]]) -> dict[str, Any] | None:
    for issue in issues:
        body = issue.get("body") or ""
        if ISSUE_MARKER in body:
            return issue
    for issue in issues:
        if str(issue.get("title", "")).startswith("Weekly update failed:"):
            return issue
    return None


def _normalise_summary(summary: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    summary = summary or {}
    source = summary.get("source") or {}
    totals = summary.get("totals") or {}
    return source, totals


def _build_body(
    *,
    automation_branch: str,
    run_id: str,
    error: str,
    summary: dict[str, Any] | None,
) -> str:
    source, totals = _normalise_summary(summary)

    lines = [ISSUE_MARKER, "", "Weekly automation run failed."]

    if automation_branch:
        lines.append(f"Automation branch: `{automation_branch}`")
    if run_id:
        lines.append(f"Run ID: `{run_id}`")

    packages = totals.get("packages")
    versions = totals.get("versions")
    if packages is not None or versions is not None:
        lines.append("")
        lines.append("Latest compromised snapshot totals:")
        if packages is not None:
            lines.append(f"- Packages: {packages}")
        if versions is not None:
            lines.append(f"- Versions: {versions}")

    source_url = source.get("url") or SAFEDEP_FEED_URL
    retrieved_at = source.get("retrievedAt")
    content_hash = source.get("contentHash")

    lines.append("")
    lines.append("SafeDep source metadata:")
    lines.append(f"- Feed URL: {source_url}")
    if retrieved_at:
        lines.append(f"- Retrieved at: {retrieved_at}")
    if content_hash:
        lines.append(f"- Content hash: `{content_hash}`")

    lines.append("")
    lines.append("Error details:")
    lines.append("```")
    lines.append(error.strip())
    lines.append("```")

    return "\n".join(lines) + "\n"


def ensure_failure_issue(
    *,
    repository: str,
    token: str,
    automation_branch: str,
    run_id: str,
    error: str,
    summary: dict[str, Any] | None,
) -> str:
    """Create or update the weekly failure issue and return its HTML URL."""

    base_url = f"https://api.github.com/repos/{repository}/issues"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }

    response = requests.get(
        base_url,
        params={"state": "open", "per_page": 50},
        headers=headers,
        timeout=10,
    )
    response.raise_for_status()

    issues = response.json()
    target = _select_issue(issues if isinstance(issues, list) else [])

    body = _build_body(
        automation_branch=automation_branch,
        run_id=run_id,
        error=error,
        summary=summary,
    )
    title = f"Weekly update failed: {_today():%Y-%m-%d}"

    payload = {"title": title, "body": body, "labels": ISSUE_LABELS}

    if target:
        issue_url = target.get("url")
        patch = requests.patch(issue_url, json=payload, headers=headers, timeout=10)
        patch.raise_for_status()
        return patch.json().get("html_url", "")

    post = requests.post(base_url, json=payload, headers=headers, timeout=10)
    post.raise_for_status()
    return post.json().get("html_url", "")
