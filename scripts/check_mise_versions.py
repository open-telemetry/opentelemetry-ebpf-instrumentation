# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
"""Check that Mise's install pins match the repository's canonical versions."""

import re
import sys
from pathlib import Path

import tomllib


def required_match(pattern: str, text: str, label: str) -> str:
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {label}, found {len(matches)}")
    return matches[0]


def check_versions(root: Path) -> None:
    mise = tomllib.loads((root / "mise.toml").read_text())
    tools = mise.get("tools")
    if tools is None:
        raise ValueError("mise.toml must contain a [tools] table")
    if not isinstance(tools, dict):
        raise TypeError("mise.toml [tools] must be a table")
    go_mod = (root / "go.mod").read_text()
    deps = (root / "dependencies.Dockerfile").read_text()
    tools_mod = (root / "internal/tools/go.mod").read_text()
    lock = tomllib.loads((root / "mise.lock").read_text())

    mise_go = tools.get("go")
    if not isinstance(mise_go, str):
        raise TypeError("mise.toml [tools].go must be a version string")
    go_toolchain = required_match(r"^toolchain\s+(\S+)$", go_mod, "Go toolchain")
    docker_go = required_match(
        r"^FROM\s+golang:([^\s@]+)(?:@[^\s]+)?\s+AS\s+golang\s*$",
        deps,
        "golang dependencies image",
    )
    mise_lint = tools.get("golangci-lint")
    if not isinstance(mise_lint, str):
        raise TypeError("mise.toml [tools].golangci-lint must be a version string")
    module_lint = required_match(
        r"^\s*github\.com/golangci/golangci-lint/v2\s+(v\S+)",
        tools_mod,
        "tools module golangci-lint version",
    )

    expected_go = go_toolchain.removeprefix("go")
    expected_lint = module_lint.removeprefix("v")
    if mise_go != expected_go:
        raise ValueError(
            f"Mise Go {mise_go} does not match go.mod toolchain {expected_go}"
        )
    if docker_go != expected_go:
        raise ValueError(
            f"dependencies.Dockerfile golang image {docker_go} does not match "
            f"go.mod toolchain {expected_go}"
        )
    if mise_lint != expected_lint:
        raise ValueError(
            f"Mise golangci-lint {mise_lint} does not match internal/tools/go.mod {expected_lint}"
        )

    locked_tools = lock.get("tools", {})
    for name, expected in (("go", expected_go), ("golangci-lint", expected_lint)):
        entries = locked_tools.get(name, [])
        if len(entries) != 1 or entries[0].get("version") != expected:
            locked = (
                entries[0].get("version")
                if len(entries) == 1
                else "missing or duplicated"
            )
            raise ValueError(
                f"mise.lock {name} {locked} does not match canonical version {expected}"
            )


def main() -> int:
    root = (
        Path(sys.argv[1])
        if len(sys.argv) == 2
        else Path(__file__).resolve().parent.parent
    )
    try:
        check_versions(root)
    except (OSError, TypeError, ValueError) as error:
        print(f"Mise version parity check failed: {error}", file=sys.stderr)
        return 1
    print("Mise tool versions match their canonical declarations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
