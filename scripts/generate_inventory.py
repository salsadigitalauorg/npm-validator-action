#!/usr/bin/env python3
"""Generate inventory and summary outputs for npm-validator scans."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def load_compromised(source: str) -> dict[str, list[str]]:
    if not source:
        return {}
    if source.startswith("http://") or source.startswith("https://"):
        import requests

        resp = requests.get(source, timeout=20)
        resp.raise_for_status()
        return json.loads(resp.text)
    path = Path(source)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def discover_inventory(root: Path) -> dict[Path, dict[str, str]]:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

    from npm_validator.discovery import discover_manifests
    from npm_validator.parsers.package_lock import parse as parse_package_lock
    from npm_validator.parsers.pnpm_lock import parse as parse_pnpm_lock
    from npm_validator.parsers.yarn_lock import parse as parse_yarn_lock

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
    compromised: dict[str, list[str]],
    psa_id: str | None,
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

    for project_path, packages in projects:
        rel = project_path.relative_to(root)
        markdown_lines.append(f"## {rel}")
        markdown_lines.append("")
        markdown_lines.append("| Package | Installed | Status | Compromised Versions |")
        markdown_lines.append("| --- | --- | --- | --- |")

        for name, version in sorted(packages.items()):
            compromised_versions = compromised.get(name, [])
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
        "versions against the compromised package list to highlight lockfiles that may be "
        "impacted by the maintainer account takeover supply-chain attack described in "
        f"{psa_reference}."
    )

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
        "",
    ]

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
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    compromised = load_compromised(args.list)
    inventory = discover_inventory(root)
    summary_md, inventory_txt = build_outputs(
        root,
        report,
        inventory,
        compromised,
        args.psa_id,
    )

    Path(args.summary).write_text(summary_md, encoding="utf-8")
    Path(args.inventory).write_text(inventory_txt, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
