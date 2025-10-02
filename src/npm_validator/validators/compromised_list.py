"""CLI entrypoint for validating the compromised packages snapshot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from collections.abc import Iterable

from jsonschema import Draft202012Validator

_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_SCHEMA = _ROOT / "specs" / "002-i-need-your" / "contracts" / "compromised-list.schema.json"
_DEFAULT_INPUT = _ROOT / "data" / "compromised_packages.json"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _format_errors(errors: Iterable) -> str:
    messages = []
    for error in errors:
        pointer = "/".join(str(p) for p in error.path)
        messages.append(f"- {pointer or '<root>'}: {error.message}")
    return "\n".join(messages)


def validate_snapshot(input_path: Path, schema_path: Path) -> None:
    schema = _load_json(schema_path)
    document = _load_json(input_path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: e.path)
    if errors:
        raise ValueError("\n" + _format_errors(errors))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=_DEFAULT_INPUT,
        help="Path to the JSON snapshot to validate",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=_DEFAULT_SCHEMA,
        help="Path to the JSON schema used for validation",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        validate_snapshot(args.input, args.schema)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"ERROR: Failed to read JSON: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"ERROR: Snapshot failed validation:{exc}", file=sys.stderr)
        return 1

    print(f"Snapshot {args.input} is valid against {args.schema}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
