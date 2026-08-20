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
from .parsers.package_lock import describe_match_from_metadata as describe_package_lock_match
from .parsers.package_lock import inspect as inspect_package_lock
from .parsers.package_lock import parse as parse_package_lock
from .parsers.pnpm_lock import parse as parse_pnpm_lock
from .parsers.semver import satisfies as semver_satisfies
from .parsers.yarn_lock import parse as parse_yarn_lock
from .report import aggregate
from . import issues as issues_mod


def _matches_compromised(installed: str, compromised_versions: list[str]) -> bool:
    return any(semver_satisfies(installed, expr) for expr in compromised_versions)


def _patch_package_enabled(project: Path) -> bool:
    package_json = project / "package.json"
    try:
        payload = json.loads(package_json.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return False

    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return False
    postinstall = scripts.get("postinstall")
    return isinstance(postinstall, str) and "patch-package" in postinstall


def _package_instance_from_patch_path(path: str) -> str | None:
    path = path.removeprefix("a/").removeprefix("b/")
    parts = [part for part in path.split("/") if part]
    indexes = [index for index, part in enumerate(parts) if part == "node_modules"]
    if not indexes:
        return None

    index = indexes[-1]
    if index + 1 >= len(parts):
        return None

    end = index + 2
    if parts[index + 1].startswith("@") and index + 2 < len(parts):
        end = index + 3
    return "/".join(parts[:end])


def _patch_paths_for_instances(
    root: Path, project: Path, instances: list[str]
) -> list[dict[str, str]]:
    """Return patch-package files that reference matched lockfile instances.

    This is evidence that patch-package targets the installed instance; it does
    not prove the patch content is a complete remediation.
    """

    if not instances or not _patch_package_enabled(project):
        return []

    patch_dir = project / "patches"
    if not patch_dir.is_dir():
        return []

    wanted = set(instances)
    patches: dict[tuple[str, str], dict[str, str]] = {}
    for patch_file in sorted(patch_dir.glob("*.patch")):
        try:
            content = patch_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in content.splitlines():
            if line.startswith("diff --git "):
                candidates = line.split()[2:4]
            elif line.startswith("--- ") or line.startswith("+++ "):
                candidates = line.split()[1:2]
            else:
                continue
            for candidate in candidates:
                instance = _package_instance_from_patch_path(candidate)
                if instance in wanted:
                    patch_path = str(patch_file.relative_to(root))
                    patches[(patch_path, instance)] = {
                        "patchPath": patch_path,
                        "packageLockInstance": instance,
                    }

    return [patches[key] for key in sorted(patches)]


def scan_repository(
    root: Path,
    list_source: str | None = None,
    warn_only: bool = False,
    scan_context: str = "repo",
) -> dict[str, Any]:
    """Scan a repository for compromised packages.

    Params:
        root: repository root to scan
        list_source: optional URL or filesystem path for list JSON; when None,
            the caller should provide a default (e.g., packaged data file or
            ref-pinned URL in the Action)
        warn_only: if True, findings do not fail the workflow (exit 0)
        scan_context: label describing where the scan was performed

    Returns: dict report matching the report contract fixture under
        tests/contracts/fixtures/report.schema.json

    NOTE: Minimal implementation to satisfy T011–T014 test flows.
    """
    root = root.resolve()

    compromised = _load_compromised_list(list_source)

    # Discover manifests
    manifest_paths = discover_manifests(root)

    # Group by project (parent directory)
    by_project: dict[Path, list[tuple[str, str]]] = {}
    finding_metadata: dict[Path, dict[tuple[str, str], dict[str, Any]]] = {}
    for p in manifest_paths:
        proj = p.parent
        by_project.setdefault(proj, [])
        finding_metadata.setdefault(proj, {})
        manifest_path = str(p.relative_to(root))
        if p.name == "package-lock.json":
            package_lock_metadata = inspect_package_lock(p)
            for name, version in parse_package_lock(p):
                pair = (name, version)
                if pair not in by_project[proj]:
                    by_project[proj].append(pair)
                finding_metadata[proj][pair] = {
                    "dependencyType": "unknown",
                    "dependencyPath": [],
                    "evidence": {
                        "lockfileType": "npm",
                        "manifestPath": manifest_path,
                        "scanContext": scan_context,
                    },
                    **describe_package_lock_match(
                        package_lock_metadata,
                        package_name=name,
                        version=version,
                    ),
                }
        elif p.name == "pnpm-lock.yaml":
            for name, version in parse_pnpm_lock(p):
                pair = (name, version)
                if pair not in by_project[proj]:
                    by_project[proj].append(pair)
                finding_metadata[proj][pair] = {
                    "dependencyType": "unknown",
                    "dependencyPath": [],
                    "evidence": {
                        "lockfileType": "pnpm",
                        "manifestPath": manifest_path,
                        "scanContext": scan_context,
                    },
                }
        elif p.name == "yarn.lock":
            for name, version in parse_yarn_lock(p):
                pair = (name, version)
                if pair not in by_project[proj]:
                    by_project[proj].append(pair)
                finding_metadata[proj][pair] = {
                    "dependencyType": "unknown",
                    "dependencyPath": [],
                    "evidence": {
                        "lockfileType": "yarn",
                        "manifestPath": manifest_path,
                        "scanContext": scan_context,
                    },
                }

    projects: list[dict[str, Any]] = []
    for proj, installed in sorted(by_project.items(), key=lambda kv: str(kv[0])):
        findings: list[dict[str, Any]] = []
        for name, version in installed:
            compromised_versions = compromised.get(name, [])
            if _matches_compromised(version, compromised_versions):
                metadata = finding_metadata.get(proj, {}).get((name, version), {})
                package_lock_instances = metadata.get("packageLockInstances", [])
                findings.append(
                    {
                        "package": name,
                        "installed": version,
                        "compromised": compromised_versions,
                        "dependencyType": metadata.get("dependencyType", "unknown"),
                        "dependencyPath": metadata.get("dependencyPath", []),
                        "evidence": metadata.get(
                            "evidence",
                            {
                                "manifestPath": "",
                                "scanContext": scan_context,
                            },
                        ),
                        "packageLockInstances": package_lock_instances,
                        "patches": _patch_paths_for_instances(
                            root,
                            proj,
                            package_lock_instances,
                        ),
                    }
                )

        projects.append(
            {
                "path": str(proj.relative_to(root)),
                "findings": findings,
            }
        )

    report = aggregate(projects, scan_context=scan_context)

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
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    r = session.get(url, timeout=(5, 15))
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


def _allowed_list_roots() -> list[Path]:
    """Roots that filesystem ``list_source`` paths must resolve inside.

    Only enforced when running as the composite action (``GITHUB_ACTION_PATH``
    is set, which happens only during ``uses:`` of a local/composite action).
    Pytest, the standalone CLI, and plain workflow ``run:`` steps remain
    unrestricted, since their ``--list`` values are operator-controlled.
    """

    action_path = os.getenv("GITHUB_ACTION_PATH")
    if not action_path:
        return []
    roots: list[Path] = [Path(action_path).resolve()]
    workspace = os.getenv("GITHUB_WORKSPACE")
    if workspace:
        roots.append(Path(workspace).resolve())
    return roots


def _validate_list_path(p: Path) -> Path:
    resolved = p.resolve()
    roots = _allowed_list_roots()
    if not roots:
        return resolved
    for root in roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise ValueError(
        f"list path {resolved} is outside permitted roots: " + ", ".join(str(r) for r in roots)
    )


def _load_compromised_list(list_source: str | None) -> dict[str, list[str]]:
    # If explicit source provided
    if list_source:
        if list_source.startswith("http://") or list_source.startswith("https://"):
            text = _http_get(list_source)
            return _coerce_compromised_payload(json.loads(text))
        p = _validate_list_path(Path(list_source))
        return _coerce_compromised_payload(json.loads(p.read_text(encoding="utf-8")))

    # Default: pinned to action ref
    url = _resolve_default_list_url()
    text = _http_get(url)
    return _coerce_compromised_payload(json.loads(text))
