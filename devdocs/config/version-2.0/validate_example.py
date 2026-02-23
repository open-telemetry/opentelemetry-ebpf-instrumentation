#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Validate an OBI v2 extension example against the local JSON schema."
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=here / "obi-extension.schema.json",
        help="Path to the OBI extension JSON schema.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=here / "examples" / "default-configuration.yaml",
        help="Path to a full OTel declarative YAML config.",
    )
    parser.add_argument(
        "--subtree",
        type=str,
        default="extensions.obi",
        help="Dot path in the YAML document to validate (default: extensions.obi).",
    )
    parser.add_argument(
        "--max-errors",
        type=int,
        default=20,
        help="Maximum number of validation errors to print.",
    )
    return parser.parse_args()


def get_subtree(data: object, dot_path: str) -> object:
    current = data
    for key in [segment for segment in dot_path.split(".") if segment]:
        if not isinstance(current, dict) or key not in current:
            raise KeyError(f"Missing path segment: {key}")
        current = current[key]
    return current


def main() -> int:
    args = parse_args()

    try:
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Failed to read schema file {args.schema}: {exc}", file=sys.stderr)
        return 2

    try:
        document = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Failed to read config file {args.config}: {exc}", file=sys.stderr)
        return 2

    try:
        instance = get_subtree(document, args.subtree)
    except KeyError as exc:
        print(f"Invalid subtree path '{args.subtree}': {exc}", file=sys.stderr)
        return 2

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda err: list(err.path))

    if not errors:
        print(
            f"VALID: {args.config} -> {args.subtree} conforms to {args.schema}"
        )
        return 0

    print(
        f"INVALID: {args.config} -> {args.subtree} has {len(errors)} validation error(s)"
    )
    for err in errors[: max(args.max_errors, 1)]:
        path = ".".join(str(x) for x in err.path) or "<root>"
        print(f"- {path}: {err.message}")

    if len(errors) > args.max_errors:
        print(f"... {len(errors) - args.max_errors} more error(s) omitted")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
