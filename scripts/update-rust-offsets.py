#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Generate Rust offsets for the latest four compiler minors and pinned libraries."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from rust_context import FIXTURE, REPO, VERSIONS, build, build_lock, load_versions, prepare_dependencies


def latest_toolchains(tags):
    releases = {}
    for line in tags.splitlines():
        match = re.search(r"refs/tags/(1\.(\d+)\.(\d+))$", line)
        if match:
            version, minor, patch = match.groups()
            minor, patch = int(minor), int(patch)
            if minor not in releases or patch > releases[minor][0]:
                releases[minor] = patch, version
    if len(releases) < 4:
        raise ValueError("Rust release tags do not contain four stable compiler minors")
    return [releases[minor][1] for minor in sorted(releases)[-4:]]


def fixture_digest(case, lock):
    digest = hashlib.sha256(b"release-symbols-v1" + json.dumps(case, sort_keys=True).encode())
    files = [FIXTURE / "Cargo.toml", REPO / "internal/rustexec/dwarf.go"]
    files.append(lock)
    files.extend(sorted((FIXTURE / "src").rglob("*.rs")))
    for path in files:
        digest.update(path.read_bytes())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--output", type=Path, default=REPO / "pkg/internal/ebpf/generictracer/rust_offsets.json")
    parser.add_argument("--toolchains", help="comma-separated compiler releases")
    parser.add_argument("--targets", help="comma-separated Rust targets")
    parser.add_argument("--case", action="append", help="limit generation to named fixtures")
    parser.add_argument("--offline", action="store_true", help="use installed compilers and cached Cargo dependencies")
    parser.add_argument("--force", action="store_true", help="rebuild previously measured fixtures")
    parser.add_argument("--refresh-locks", action="store_true", help="refresh dependency locks in the work directory")
    args = parser.parse_args()
    versions = load_versions()
    if args.toolchains:
        toolchains = args.toolchains.split(",")
    elif args.offline:
        toolchains = versions["toolchains"]
    else:
        refs = subprocess.check_output(["git", "ls-remote", "--tags", "https://github.com/rust-lang/rust.git"], text=True)
        toolchains = latest_toolchains(refs)
    targets = args.targets.split(",") if args.targets else versions["targets"]
    cases = [case for case in versions["cases"] if not args.case or case["name"] in args.case]
    if not cases or args.case and set(args.case) - {case["name"] for case in cases}:
        parser.error("unknown or empty Rust fixture selection")
    work = args.work_dir or Path(tempfile.mkdtemp(prefix="obi-rust-offsets-"))
    work.mkdir(parents=True, exist_ok=True)
    database = json.loads(args.output.read_text()) if args.output.exists() else {"profiles": []}
    measured = database.setdefault("measurements", {})
    inspector = work / "rust-offsets"
    subprocess.run(["go", "build", "-o", str(inspector), "./scripts/rust-offsets"], cwd=REPO, check=True)
    for toolchain in toolchains:
        if not args.offline:
            subprocess.run(["rustup", "toolchain", "install", toolchain, "--profile", "minimal", "--target", ",".join(targets)], check=True)
        for case in cases:
            with build_lock(work):
                manifest = prepare_dependencies(case, work / toolchain / case["name"], toolchain,
                                                args.offline, args.refresh_locks)
                digest = fixture_digest(case, manifest.with_name("Cargo.lock"))
            for target in targets:
                key = f"{toolchain}/{target}/{case['name']}"
                if not args.force and not args.refresh_locks and measured.get(key) == digest:
                    continue
                print("Generating " + key, flush=True)
                binary = build(case, work, toolchain, target, offsets=True, offline=args.offline)
                release = build(case, work, toolchain, target, offline=args.offline)
                subprocess.run([str(inspector), "-binary", str(binary), "-symbols", str(release), "-output", str(args.output)], cwd=REPO, check=True)
                measured[key] = digest
                database = json.loads(args.output.read_text())
                database["measurements"] = measured
                temporary = args.output.with_suffix(".json.tmp")
                temporary.write_text(json.dumps(database, indent=2) + "\n")
                temporary.replace(args.output)
    if not args.toolchains and not args.targets and not args.case:
        versions["toolchains"] = toolchains
        VERSIONS.write_text(json.dumps(versions, indent=2) + "\n")


if __name__ == "__main__":
    main()
