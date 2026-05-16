#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


DEFAULT_OTEL_SCHEMA_URL = (
    "https://raw.githubusercontent.com/open-telemetry/opentelemetry-configuration/"
    "49c531f78f86b85e220ec23c5be1a925254f0f9d/opentelemetry_configuration.json"
)


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
    parser.add_argument(
        "--otel-schema-url",
        type=str,
        default=DEFAULT_OTEL_SCHEMA_URL,
        help="URL for full-document OTel declarative JSON schema validation.",
    )
    parser.add_argument(
        "--skip-otel",
        action="store_true",
        help="Skip full-document OTel declarative schema validation.",
    )
    return parser.parse_args()


def get_subtree(data: object, dot_path: str) -> object:
    current = data
    for key in [segment for segment in dot_path.split(".") if segment]:
        if not isinstance(current, dict) or key not in current:
            raise KeyError(f"Missing path segment: {key}")
        current = current[key]
    return current


def print_errors(errors: list, max_errors: int) -> None:
    for err in errors[: max(max_errors, 1)]:
        path = ".".join(str(x) for x in err.path) or "<root>"
        print(f"- {path}: {err.message}")
    if len(errors) > max_errors:
        print(f"... {len(errors) - max_errors} more error(s) omitted")


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
        print(f"OBI VALID: {args.config} -> {args.subtree} conforms to {args.schema}")
    else:
        print(
            f"OBI INVALID: {args.config} -> {args.subtree} has {len(errors)} validation error(s)"
        )
        print_errors(errors, args.max_errors)

    otel_errors = []
    if args.skip_otel:
        print("OTEL SKIPPED: full-document OTel validation disabled by --skip-otel")
    else:
        try:
            with urllib.request.urlopen(args.otel_schema_url, timeout=30) as response:
                otel_schema = json.load(response)
        except Exception as exc:
            print(
                f"Failed to load OTel schema from {args.otel_schema_url}: {exc}",
                file=sys.stderr,
            )
            return 2

        otel_validator = Draft202012Validator(otel_schema)
        otel_errors = sorted(
            otel_validator.iter_errors(document), key=lambda err: list(err.path)
        )

        if not otel_errors:
            print(
                f"OTEL VALID: {args.config} conforms to OTel schema from {args.otel_schema_url}"
            )
        else:
            print(
                f"OTEL INVALID: {args.config} has {len(otel_errors)} validation error(s)"
            )
            print_errors(otel_errors, args.max_errors)

    return 0 if not errors and (args.skip_otel or not otel_errors) else 1


if __name__ == "__main__":
    raise SystemExit(main())
