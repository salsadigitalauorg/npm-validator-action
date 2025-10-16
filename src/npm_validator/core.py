"""Core scanning entrypoints.

This module MUST NOT contain GitHub-specific dependencies so it can be used by
both the Action wrapper and a future standalone CLI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import json
import os

from .discovery import discover_manifests
from .parsers.package_lock import parse as parse_package_lock
from .parsers.pnpm_lock import parse as parse_pnpm_lock
from .parsers.yarn_lock import parse as parse_yarn_lock
from .report import aggregate
from . import issues as issues_mod


def scan_repository(
    root: Path,
    list_source: str | None = None,
    warn_only: bool = False,
) -> dict[str, Any]:
    """Scan a repository for compromised packages.

    Params:
        root: repository root to scan
        list_source: optional URL or filesystem path for list JSON; when None,
            the caller should provide a default (e.g., packaged data file or
            ref-pinned URL in the Action)
        warn_only: if True, findings do not fail the workflow (exit 0)

    Returns: dict report matching the JSON schema (see specs/contracts)

    NOTE: Minimal implementation to satisfy T011–T014 test flows.
    """
    root = root.resolve()

    compromised = _load_compromised_list(list_source)

    # Discover manifests
    manifest_paths = discover_manifests(root)

    # Group by project (parent directory)
    by_project: dict[Path, dict[str, str]] = {}
    for p in manifest_paths:
        proj = p.parent
        by_project.setdefault(proj, {})
        if p.name == "package-lock.json":
            for name, version in parse_package_lock(p):
                by_project[proj][name] = version
        elif p.name == "pnpm-lock.yaml":
            for name, version in parse_pnpm_lock(p):
                by_project[proj][name] = version
        elif p.name == "yarn.lock":
            for name, version in parse_yarn_lock(p):
                by_project[proj][name] = version

    projects: list[dict[str, Any]] = []
    for proj, installed in sorted(by_project.items(), key=lambda kv: str(kv[0])):
        findings: list[dict[str, Any]] = []
        for name, version in installed.items():
            compromised_versions = compromised.get(name, [])
            if version in compromised_versions:
                findings.append(
                    {
                        "package": name,
                        "installed": version,
                        "compromised": compromised_versions,
                    }
                )

        projects.append(
            {
                "path": str(proj.relative_to(root)),
                "findings": findings,
            }
        )

    report = aggregate(projects)

    # Optional: create/update GitHub issue when enabled and findings exist
    create_issue_env = os.getenv("NPM_VALIDATOR_CREATE_GH_ISSUE", "").strip().lower()
    if report.get("hasFindings") and create_issue_env in {"1", "true", "yes", "y"}:
        token = os.getenv("GITHUB_TOKEN", "")
        repository = os.getenv("GITHUB_REPOSITORY", "")
        try:
            # Best-effort; surface errors to caller if token missing
            if not token or not repository:
                raise RuntimeError("Missing GITHUB_TOKEN or GITHUB_REPOSITORY for issue creation")
            issues_mod.create_or_update_issue(report, token=token, repository=repository)
        except Exception:
            # Do not crash core scanning; this is an optional enhancement
            pass

    return report


# ---- List source resolution & download -------------------------------------------------


def _resolve_default_list_url() -> str:
    repo = os.getenv("GITHUB_ACTION_REPOSITORY", "salsadigitalauorg/npm-validator")
    ref = os.getenv("GITHUB_ACTION_REF", "main")
    return f"https://raw.githubusercontent.com/{repo}/{ref}/data/compromised_packages.json"


def _http_get(url: str) -> str:  # pragma: no cover - patched in tests
    import requests

    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.text


def _coerce_compromised_payload(data: Any) -> dict[str, list[str]]:
    """Normalise various payload shapes into a package -> versions mapping."""

    if isinstance(data, dict):
        packages = data.get("packages")
        if isinstance(packages, list):
            normalised: dict[str, list[str]] = {}
            for entry in packages:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                versions = entry.get("versions", [])
                if isinstance(name, str):
                    normalised[name] = [str(v) for v in versions or []]
            if normalised:
                return normalised

        if all(isinstance(v, list) for v in data.values()):
            return {str(k): [str(vv) for vv in (v or [])] for k, v in data.items()}

    raise ValueError("Unsupported compromised list format")


def _load_compromised_list(list_source: str | None) -> dict[str, list[str]]:
    # If explicit source provided
    if list_source:
        if list_source.startswith("http://") or list_source.startswith("https://"):
            text = _http_get(list_source)
            return _coerce_compromised_payload(json.loads(text))
        p = Path(list_source)
        return _coerce_compromised_payload(json.loads(p.read_text(encoding="utf-8")))

    # Default: pinned to action ref
    url = _resolve_default_list_url()
    text = _http_get(url)
    return _coerce_compromised_payload(json.loads(text))
