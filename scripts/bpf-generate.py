#!/usr/bin/env python3
"""Run only the bpf2go packages whose generated outputs are missing or stale."""

from __future__ import annotations

import os
import hashlib
import json
import re
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SUPPORTED_ARCHES = {"amd64", "arm64"}
DEFAULT_CFLAGS = "-std=gnu17 -O2 -g -Wunaligned-access -Wpacked -Wpadded -Wall -Werror"
FINGERPRINT_FILE = ROOT / ".mise" / "bpf-generate-fingerprint.json"


def selected_arches() -> list[str]:
    values = os.environ.get("BPF_TARGETS", "amd64,arm64").split(",")
    arches = sorted({value.strip() for value in values if value.strip()})
    if not arches:
        raise SystemExit("BPF_TARGETS is empty; use amd64, arm64, or both")
    unsupported = sorted(set(arches) - SUPPORTED_ARCHES)
    if unsupported:
        raise SystemExit(f"Unsupported BPF_TARGETS: {', '.join(unsupported)} (supported: amd64, arm64)")
    return arches


def dependency_rules(path: Path) -> list[tuple[list[Path], list[Path]]]:
    contents = path.read_text().replace("\\\n", " ")
    rules = []
    for line in contents.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        target_text, dependency_text = line.split(":", 1)
        try:
            targets = [ROOT / token for token in shlex.split(target_text)]
            dependencies = [ROOT / token for token in shlex.split(dependency_text)]
        except ValueError as error:
            raise SystemExit(f"Cannot parse bpf2go dependency file {path}: {error}") from error
        if targets:
            rules.append((targets, dependencies))
    return rules


def generation_directives() -> dict[Path, list[tuple[str, str]]]:
    """Return package -> (output prefix, directive) pairs."""
    directives: dict[Path, list[tuple[str, str]]] = {}
    for source in (ROOT / "pkg").rglob("*.go"):
        for line in source.read_text(errors="ignore").splitlines():
            if not line.startswith("//go:generate") or "BPF2GO" not in line:
                continue
            try:
                tokens = shlex.split(line.removeprefix("//go:generate").strip())
            except ValueError as error:
                raise SystemExit(f"Cannot parse bpf2go directive in {source}: {error}") from error
            c_index = next((i for i, token in enumerate(tokens) if token.endswith(".c")), None)
            if c_index is None or c_index == 0:
                raise SystemExit(f"Cannot determine bpf2go output prefix in {source}: {line}")
            directives.setdefault(source.parent, []).append((tokens[c_index - 1], line))
    return directives


def fingerprint(package_directives: list[tuple[str, str]], arch: str) -> str:
    material = "\n".join(line for _, line in package_directives)
    material += f"\narch={arch}\nclang={os.environ.get('BPF_CLANG', os.environ.get('CLANG', 'clang'))}"
    bpf2go = os.environ.get("BPF2GO", "")
    if not bpf2go or bpf2go == str(ROOT / ".tools" / "bpf2go"):
        bpf2go = "go tool -modfile=internal/tools/go.mod bpf2go"
    material += f"\nbpf2go={bpf2go}"
    material += f"\ncflags={os.environ.get('BPF_CFLAGS', ' '.join((DEFAULT_CFLAGS, os.environ.get('CFLAGS', ''))).strip())}"
    for path in (ROOT / "internal/tools/go.mod", ROOT / "internal/tools/go.sum"):
        if path.exists():
            material += f"\n{path.name}={path.read_text()}"
    return hashlib.sha256(material.encode()).hexdigest()


def read_fingerprints() -> dict[str, str]:
    try:
        return json.loads(FINGERPRINT_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def stale_targets(
    arches: list[str],
    directives: dict[Path, list[tuple[str, str]]],
    recorded: dict[str, str],
) -> set[tuple[Path, str]]:
    arch_suffixes = {"amd64": "x86", "arm64": "arm64"}
    stale: set[tuple[Path, str]] = set()
    for package, package_directives in directives.items():
        for arch in arches:
            suffix = arch_suffixes[arch]
            if recorded.get(f"{package.relative_to(ROOT)}:{arch}") != fingerprint(package_directives, arch):
                stale.add((package, arch))
                continue
            for prefix, _ in package_directives:
                output_prefix = prefix.lower()
                generated = package / f"{output_prefix}_{suffix}_bpfel.go"
                obj = package / f"{output_prefix}_{suffix}_bpfel.o"
                depfile = package / f"{output_prefix}_{suffix}_bpfel.go.d"
                if not all(path.is_file() for path in (generated, obj, depfile)):
                    stale.add((package, arch))
                    break
                rules = dependency_rules(depfile)
                if not rules:
                    stale.add((package, arch))
                    break
                for targets, dependencies in rules:
                    if any(not target.exists() for target in targets):
                        stale.add((package, arch))
                        break
                    newest_output = min(target.stat().st_mtime_ns for target in targets)
                    if any(not dep.exists() or dep.stat().st_mtime_ns > newest_output for dep in dependencies):
                        stale.add((package, arch))
                        break
                if (package, arch) in stale:
                    break
    return stale


def run_generation(
    targets: set[tuple[Path, str]],
    directives: dict[Path, list[tuple[str, str]]],
    recorded: dict[str, str],
) -> None:
    env = os.environ.copy()
    env["BPF_CLANG"] = os.environ.get("BPF_CLANG", os.environ.get("CLANG", "clang"))
    env["BPF_CFLAGS"] = os.environ.get("BPF_CFLAGS", " ".join((DEFAULT_CFLAGS, os.environ.get("CFLAGS", ""))).strip())
    if not env.get("BPF2GO"):
        env["BPF2GO"] = str(ROOT / ".tools" / "bpf2go")
    env["BPF2GO_MAKEBASE"] = str(ROOT)

    if env["BPF2GO"] == str(ROOT / ".tools" / "bpf2go"):
        wrapper = Path(env["BPF2GO"])
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        wrapper.write_text(
            f"#!/bin/sh\nexec go tool -modfile={ROOT / 'internal/tools/go.mod'} bpf2go \"$@\"\n"
        )
        wrapper.chmod(0o755)

    generated: list[tuple[Path, str]] = []
    packages = sorted({package for package, _ in targets})
    for package in packages:
        package_arches = sorted(arch for target_package, arch in targets if target_package == package)
        relative = package.relative_to(ROOT).as_posix()

        def generate_arch(arch: str) -> str:
            arch_env = env.copy()
            arch_env["BPF_TARGETS"] = arch
            print(f"Generating {relative} for {arch}...", flush=True)
            subprocess.run(
                ["go", "generate", "-run", "BPF2GO", f"./{relative}"],
                cwd=ROOT,
                env=arch_env,
                check=True,
            )
            return arch

        with ThreadPoolExecutor(max_workers=len(package_arches)) as executor:
            generated.extend((package, arch) for arch in executor.map(generate_arch, package_arches))

    for package, arch in generated:
        key = f"{package.relative_to(ROOT)}:{arch}"
        recorded[key] = fingerprint(directives[package], arch)

    FINGERPRINT_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = FINGERPRINT_FILE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(recorded, indent=2, sort_keys=True) + "\n")
    temporary.replace(FINGERPRINT_FILE)


def main() -> None:
    arches = selected_arches()
    force = "--all" in sys.argv[1:]
    directives = generation_directives()
    recorded = read_fingerprints()
    if force:
        targets = {(package, arch) for package in directives for arch in arches}
        run_generation(targets, directives, recorded)
        return

    stale = stale_targets(arches, directives, recorded)
    if stale:
        print(f"Regenerating {len(stale)} stale BPF package/architecture target(s)", flush=True)
        run_generation(stale, directives, recorded)
    else:
        print("BPF generated files are up to date")


if __name__ == "__main__":
    main()
