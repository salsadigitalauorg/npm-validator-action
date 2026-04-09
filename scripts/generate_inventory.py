#!/usr/bin/env python3
"""Generate inventory and summary outputs for npm-validator scans."""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from collections.abc import Callable
from typing import Any


def _coerce_compromised_payload(data: Any) -> dict[str, list[str]]:
    """Normalise various payload shapes into a package -> versions mapping.

    Mirrors the logic used in src/npm_validator/core.py so that this script
    works with both historical list formats and the current snapshot schema.
    """

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

        # Legacy mapping form: { "package": ["1.0.0", ...], ... }
        if all(isinstance(v, list) for v in data.values()):
            return {str(k): [str(vv) for vv in (v or [])] for k, v in data.items()}

    raise ValueError("Unsupported compromised list format")


def load_compromised(
    source: str, bundle: str | None
) -> tuple[dict[str, list[str]], dict[str, int] | None]:
    """Load the compromised list and return (mapping, totals).

    The mapping is package -> list of compromised versions.
    Totals contains overall package/version counts for the snapshot, when
    available, or is derived from the mapping as a fallback.
    """

    raw: Any | None = None

    if not source and bundle:
        with zipfile.ZipFile(bundle) as zf:
            data = zf.read("data/compromised_packages.json")
        raw = json.loads(data.decode("utf-8"))
    elif not source:
        return {}, None
    elif source.startswith("http://") or source.startswith("https://"):
        import requests

        resp = requests.get(source, timeout=20)
        resp.raise_for_status()
        raw = json.loads(resp.text)
    else:
        path = Path(source)
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
        else:
            return {}, None

    mapping = _coerce_compromised_payload(raw)

    totals: dict[str, int] | None = None
    if isinstance(raw, dict):
        maybe_totals = raw.get("totals")
        if isinstance(maybe_totals, dict):
            packages = maybe_totals.get("packages")
            versions = maybe_totals.get("versions")
            if isinstance(packages, int) and isinstance(versions, int):
                totals = {"packages": packages, "versions": versions}

    if totals is None:
        package_count = len(mapping)
        version_count = sum(len(versions) for versions in mapping.values())
        totals = {"packages": package_count, "versions": version_count}

    return mapping, totals


def load_feeds_status(list_source: str | None) -> dict[str, dict[str, Any]]:
    """Load per-feed status metrics adjacent to the compromised list, if present."""

    if not list_source:
        return {}

    # For action runs this will resolve to data/compromised_feeds_status.json
    # next to data/compromised_packages.json. For temporary copies (CLI runs),
    # the file will not exist and we simply return an empty mapping.
    if list_source.startswith("http://") or list_source.startswith("https://"):
        return {}

    status_path = Path(list_source).with_name("compromised_feeds_status.json")
    try:
        content = status_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}

    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return {}

    if not isinstance(payload, dict):
        return {}

    feeds: dict[str, dict[str, Any]] = {}
    for feed_id, feed_data in payload.items():
        if isinstance(feed_data, dict):
            feeds[str(feed_id)] = feed_data

    return feeds


def resolve_parsers(
    bundle: str | None,
) -> tuple[
    Callable[[Path], list[Path]],
    Callable[[Path], list[tuple[str, str]]],
    Callable[[Path], list[tuple[str, str]]],
    Callable[[Path], list[tuple[str, str]]],
]:
    if bundle:
        bundle_src = f"{bundle}/src"
        if bundle_src not in sys.path:
            sys.path.insert(0, bundle_src)

    script_path = Path(__file__).resolve()
    local_candidates = [script_path.parents[1] / "src", script_path.parents[2] / "src"]

    for candidate in local_candidates:
        if candidate.exists():
            sys.path.insert(0, str(candidate))
            break

    from npm_validator.discovery import discover_manifests
    from npm_validator.parsers.package_lock import parse as parse_package_lock
    from npm_validator.parsers.pnpm_lock import parse as parse_pnpm_lock
    from npm_validator.parsers.yarn_lock import parse as parse_yarn_lock

    return discover_manifests, parse_package_lock, parse_pnpm_lock, parse_yarn_lock


def discover_inventory(root: Path, bundle: str | None) -> dict[Path, dict[str, str]]:
    (
        discover_manifests,
        parse_package_lock,
        parse_pnpm_lock,
        parse_yarn_lock,
    ) = resolve_parsers(bundle)

    manifests = discover_manifests(root)
    inventory: dict[Path, dict[str, str]] = defaultdict(dict)

    for manifest in manifests:
        project = manifest.parent
        inv = inventory[project]
        if manifest.name == "package-lock.json":
            for name, version in parse_package_lock(manifest):
                inv[name] = version
        elif manifest.name == "pnpm-lock.yaml":
            for name, version in parse_pnpm_lock(manifest):
                inv[name] = version
        elif manifest.name == "yarn.lock":
            for name, version in parse_yarn_lock(manifest):
                inv[name] = version

    return inventory


def build_outputs(
    root: Path,
    report: dict,
    inventory: dict[Path, dict[str, str]],
    compromised: dict[str, list[str]] | dict[str, Any],
    psa_id: str | None,
    list_totals: dict[str, int] | None = None,
    feeds_status: dict[str, dict[str, Any]] | None = None,
) -> tuple[str, str]:
    projects = sorted(inventory.items(), key=lambda item: str(item[0]))

    markdown_lines: list[str] = []
    if psa_id:
        markdown_lines.append(f"# {psa_id} Inventory & Match Status")
    else:
        markdown_lines.append("# Inventory & Match Status")
    markdown_lines.append("")

    findings_lookup = {
        (proj.get("path"), finding.get("package"), finding.get("installed"))
        for proj in report.get("projects", [])
        for finding in proj.get("findings", [])
    }

    total_projects = len(projects)
    total_packages = sum(len(packages) for _, packages in projects)
    total_matches = 0

    text_lines: list[str] = ["project_path\tpackage\tversion\tstatus"]

    # Normalise compromised payload into package -> versions mapping
    compromised_map: dict[str, list[str]] = {}
    try:
        compromised_map = _coerce_compromised_payload(compromised)
    except ValueError:
        compromised_map = {}

    for project_path, packages in projects:
        rel = project_path.relative_to(root)
        markdown_lines.append(f"## {rel}")
        markdown_lines.append("")
        markdown_lines.append("| Package | Installed | Status | Compromised Versions |")
        markdown_lines.append("| --- | --- | --- | --- |")

        for name, version in sorted(packages.items()):
            compromised_versions = compromised_map.get(name, [])
            status = "MATCH" if version in compromised_versions else "OK"
            if (str(rel), name, version) in findings_lookup:
                status = "MATCH"
            if status == "MATCH":
                total_matches += 1
            markdown_lines.append(
                f"| {name} | {version} | {status} | {','.join(compromised_versions)} |"
            )
            text_lines.append(f"{rel}\t{name}\t{version}\t{status}")

        markdown_lines.append("")

    overall_ok = total_matches == 0
    status_label = "OK" if overall_ok else "MATCH"
    status_icon = "✅" if overall_ok else "❌"
    status_description = (
        "No compromised packages detected."
        if overall_ok
        else "Compromised packages detected; review required."
    )

    psa_reference = "[PSA-2025-09-17](https://www.drupal.org/psa-2025-09-17)"
    if psa_id and psa_id != "PSA-2025-09-17":
        psa_reference = f"{psa_reference} ({psa_id})"

    purpose_line = (
        "This check inventories npm packages across the repository and compares installed "
        "versions against a compromised package snapshot built from the configured feeds to "
        "highlight lockfiles that may be impacted by the maintainer account takeover "
        "supply-chain attack described in "
        f"{psa_reference}."
    )

    snapshot_packages = list_totals.get("packages") if list_totals else None
    snapshot_versions = list_totals.get("versions") if list_totals else None

    summary_block = [
        f"{status_icon} **Overall Status:** **{status_label}** — {status_description}",
        "",
        purpose_line,
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Projects scanned | {total_projects} |",
        f"| Packages scanned | {total_packages} |",
        f"| Matches found | {total_matches} |",
    ]

    if snapshot_packages is not None and snapshot_versions is not None:
        summary_block.extend(
            [
                f"| Compromised snapshot packages | {snapshot_packages} |",
                f"| Compromised snapshot versions | {snapshot_versions} |",
            ]
        )

    summary_block.append("")

    feeds_status = feeds_status or {}
    if feeds_status:
        summary_block.extend(
            [
                "",
                "### Compromised feeds",
                "",
                "The compromised snapshot currently aggregates the following feeds:",
                "",
                "| Feed | Feed key | Packages | Versions |",
                "| --- | --- | --- | --- |",
            ]
        )

        for feed_id in sorted(feeds_status.keys()):
            feed_data = feeds_status[feed_id] or {}
            display_name = str(feed_data.get("displayName") or feed_id)
            packages = feed_data.get("packages", "n/a")
            versions = feed_data.get("versions", "n/a")
            summary_block.append(f"| {display_name} | `{feed_id}` | {packages} | {versions} |")

        summary_block.append("")

    markdown_lines[1:1] = summary_block

    return "\n".join(markdown_lines).strip() + "\n", "\n".join(text_lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--list", required=False, default="")
    parser.add_argument("--summary", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--psa-id", required=False)
    parser.add_argument("--bundle", required=False, default=None)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    compromised, list_totals = load_compromised(args.list, args.bundle)
    feeds_status = load_feeds_status(args.list)
    inventory = discover_inventory(root, args.bundle)
    summary_md, inventory_txt = build_outputs(
        root,
        report,
        inventory,
        compromised,
        args.psa_id,
        list_totals,
        feeds_status,
    )

    Path(args.summary).write_text(summary_md, encoding="utf-8")
    Path(args.inventory).write_text(inventory_txt, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
