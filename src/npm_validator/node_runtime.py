"""Check Node.js versions against the upstream Brotli decoder advisory."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .discovery import EXCLUDES


ADVISORY = "CVE-2026-111497"
SCANNER_SOURCE = "Node.js on scanner PATH"
FIXED_RELEASES = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
_END_OF_LIFE_RELEASES = frozenset(range(16, 22)) | {23, 25}
_VERSION = re.compile(
    r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_PARTIAL_VERSION = re.compile(r"^v?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$")
_DECLARATION_FILES = {".nvmrc", ".node-version", ".tool-versions"}


def _check_version(source: str, raw_version: str) -> dict[str, str]:
    """Classify an exact upstream version without treating selectors as releases."""

    version = raw_version.strip()
    # Reject oversized input before parsing arbitrary project-supplied numbers.
    match = _VERSION.fullmatch(version) if len(version) <= 128 else None
    if match and match.group(4):
        # SemVer forbids leading zeroes in numeric prerelease identifiers.
        if any(
            len(part) > 1 and part.startswith("0") and part.isdigit()
            for part in match.group(4).split(".")
        ):
            match = None

    partial = _PARTIAL_VERSION.fullmatch(version) if len(version) <= 128 else None
    partial_release = None
    if partial:
        major = int(partial.group(1))
        minor = int(partial.group(2)) if partial.group(2) is not None else None
        fixed = FIXED_RELEASES.get(major)
        if major in _END_OF_LIFE_RELEASES or (
            fixed is not None and minor is not None and minor < fixed[1]
        ):
            partial_release = major

    if partial_release is not None:
        status = "potentially_affected"
        guidance = (
            f"All upstream Node.js releases selected by {version} may be affected by "
            f"{ADVISORY}. Upgrade and confirm the runtime in use. Vendor backports or "
            "shared Brotli libraries may change exposure."
        )
    elif not match:
        status = "unknown"
        guidance = (
            f"Cannot determine a precise Node.js version for {ADVISORY}. "
            "Resolve this selector and verify the runtime and vendor security updates."
        )
    else:
        release = tuple(int(match.group(i)) for i in (1, 2, 3))
        fixed = FIXED_RELEASES.get(release[0])
        if release[0] in _END_OF_LIFE_RELEASES:
            status = "potentially_affected"
            guidance = (
                f"Node.js {release[0]}.x is end-of-life and may be affected by {ADVISORY}. "
                "Move to a supported fixed release and confirm the runtime in use. "
                "Vendor backports or shared Brotli libraries may change exposure."
            )
        elif fixed is None:
            status = "unknown"
            guidance = (
                f"Node.js {release[0]}.x is outside the versions covered by this {ADVISORY} "
                "check. Verify the runtime with its vendor; unsupported releases may be vulnerable."
            )
        elif release < fixed or (release == fixed and match.group(4)):
            status = "potentially_affected"
            fixed_version = ".".join(str(part) for part in fixed)
            guidance = (
                f"Upstream Node.js before v{fixed_version} on this release line may be affected "
                f"by {ADVISORY}. Upgrade and confirm the runtime in use. Vendor backports or "
                "shared Brotli libraries may change exposure."
            )
        elif match.group(4):
            status = "unknown"
            guidance = (
                f"This prerelease is newer than the first upstream {ADVISORY} fix, but its "
                "version alone does not establish whether it includes that fix. Verify it with "
                "the runtime vendor."
            )
        else:
            status = "not_affected"
            fixed_version = ".".join(str(part) for part in fixed)
            guidance = (
                f"This version is at or above the upstream v{fixed_version} fix for {ADVISORY}. "
                "Confirm the runtime in use and any vendor-specific packaging."
            )

    # Selectors are untrusted project input and may contain large or multiline text.
    display_version = " ".join(version.split())[:160] or "(unspecified)"
    return {
        "source": source,
        "version": display_version,
        "status": status,
        "guidance": guidance,
    }


def _unknown(source: str, guidance: str) -> dict[str, str]:
    return {
        "source": source,
        "version": "(unavailable)",
        "status": "unknown",
        "guidance": guidance,
    }


def _check_scanner_node(root: Path) -> dict[str, str]:
    executable = shutil.which("node")
    if not executable:
        return _unknown(
            SCANNER_SOURCE,
            f"Node.js was not found on the scanner PATH; verify the runtime for {ADVISORY}.",
        )

    path = Path(executable).absolute()
    try:
        resolved_path = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return _unknown(
            SCANNER_SOURCE,
            f"Could not resolve Node.js on the scanner PATH; verify the runtime for {ADVISORY}.",
        )
    if path.is_relative_to(root) or resolved_path.is_relative_to(root):
        return _unknown(
            SCANNER_SOURCE,
            "Node.js on the scanner PATH is inside the scanned repository and was not executed. "
            f"Verify the runtime for {ADVISORY}.",
        )

    # NODE_OPTIONS can preload project code even when only requesting --version.
    env = os.environ.copy()
    env.pop("NODE_OPTIONS", None)
    try:
        # Version-manager shims may consult files in the current directory and
        # execute a project-selected binary. Probe from an empty directory.
        with tempfile.TemporaryDirectory(prefix="npm-validator-node-") as probe_dir:
            if Path(probe_dir).resolve().is_relative_to(root):
                return _unknown(
                    SCANNER_SOURCE,
                    "No safe directory is available to probe Node.js. "
                    f"Verify the runtime for {ADVISORY}.",
                )
            completed = subprocess.run(
                [str(path), "--version"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
                env=env,
                cwd=probe_dir,
            )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return _unknown(
            SCANNER_SOURCE,
            f"Could not obtain the scanner Node.js version; verify the runtime for {ADVISORY}.",
        )
    if completed.returncode != 0 or not completed.stdout.strip():
        return _unknown(
            SCANNER_SOURCE,
            f"Could not obtain the scanner Node.js version; verify the runtime for {ADVISORY}.",
        )
    return _check_version(SCANNER_SOURCE, completed.stdout)


def _check_declaration(path: Path, root: Path) -> list[dict[str, str]]:
    source = path.relative_to(root).as_posix()
    try:
        # Do not read symlinks that point outside the scanned repository.
        if not path.resolve(strict=True).is_relative_to(root):
            raise OSError("declaration resolves outside repository")
        with path.open(encoding="utf-8") as stream:
            text = stream.read(65537)
        if len(text) > 65536:
            raise ValueError("declaration is too large")
    except (OSError, UnicodeError, RuntimeError, ValueError):
        return [
            _unknown(
                source,
                f"Could not read this Node.js declaration; verify the runtime for {ADVISORY}.",
            )
        ]

    if path.name == ".nvmrc":
        # nvm strips comments and accepts metadata key/value pairs alongside
        # exactly one bare version selector.
        lines = [line.split("#", 1)[0].strip() for line in text.splitlines()]
        selections: list[str] = []
        keys: set[str] = set()
        valid = True
        for line in filter(None, lines):
            if "=" in line and not line.startswith("="):
                key = line.split("=", 1)[0].strip()
                if not key or key == "node" or key in keys:
                    valid = False
                keys.add(key)
            else:
                selections.append(line)
        if valid and len(selections) == 1:
            return [_check_version(source, selections[0])]
        return [_check_version(source, text)]

    if path.name != ".tool-versions":
        return [_check_version(source, text)]

    checks: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if parts and parts[0] == "nodejs":
            checks.extend(_check_version(source, value) for value in parts[1:] or [""])
    return checks


def scan_node_runtimes(root: Path) -> list[dict[str, str]]:
    """Check scanner PATH and Node.js declarations under *root* for the advisory.

    Repository declarations identify configured versions, not deployed runtimes.
    Unresolved selectors and versions outside the assessed release lines are unknown.
    """

    root = root.resolve()
    checks = [_check_scanner_node(root)]
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs[:] = sorted(name for name in subdirs if name not in EXCLUDES)
        for name in sorted(set(files) & _DECLARATION_FILES):
            path = Path(directory) / name
            if path.is_file() or path.is_symlink():
                checks.extend(_check_declaration(path, root))
    return checks
