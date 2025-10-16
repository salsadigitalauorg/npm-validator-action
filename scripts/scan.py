#!/usr/bin/env python3
"""Local CLI entrypoint to run the scanner outside of GitHub Actions.

Usage:
  python scripts/scan.py --root . [--list path_or_url] [--warn-only]

This calls the same core scan_repository used by the Action wrapper.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from npm_validator.core import scan_repository


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--list", dest="list_source", type=str, default=None)
    parser.add_argument("--warn-only", action="store_true")
    args = parser.parse_args()

    # NOTE: This will raise NotImplementedError until T015..T023 are completed.
    report = scan_repository(args.root, list_source=args.list_source, warn_only=args.warn_only)
    print(json.dumps(report, indent=2))

    has_findings = bool(report.get("hasFindings"))

    # Default behavior: fail on findings unless env override set or --warn-only
    if has_findings and not args.warn_only:
        warn_env = os.getenv("NPM_VALIDATOR_WARN_ONLY", "").strip().lower()
        if warn_env in {"1", "true", "yes", "y"}:
            return 0
        return 10

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
