#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Build production Rust fixtures and validate symbols, layouts, and live propagation."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

from rust_context import REPO, build, load_versions, scenarios

RUNNER_IMAGE = "golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--toolchain", action="append")
    parser.add_argument("--all-toolchains", action="store_true")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--container", action="store_true", help="isolate live tests in privileged Docker containers")
    parser.add_argument("--protocols", action="store_true")
    parser.add_argument("--fallbacks", action="store_true", help="exercise stripped hook families and partial support")
    parser.add_argument("--fallbacks-only", action="store_true", help="run live fallback checks without repeating protocol scenarios")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--case", action="append")
    parser.add_argument("--scenario", action="append", help="limit live protocol scenarios by name")
    parser.add_argument("--fallback-group", action="append", help="limit live fallback checks by hook group")
    parser.add_argument("--jobs", type=int, default=1, choices=range(1, 5))
    parser.add_argument("--generate-offsets", type=Path, help="forward to the standalone updater")
    parser.add_argument("--target")
    args = parser.parse_args()
    if args.fallbacks_only and not args.live:
        parser.error("--fallbacks-only requires --live")
    if args.fallback_group and not (args.fallbacks or args.fallbacks_only):
        parser.error("--fallback-group requires --fallbacks or --fallbacks-only")
    versions = load_versions()
    compilers = args.toolchain or (versions["toolchains"] if args.all_toolchains else versions["toolchains"][-1:])
    work = (args.work_dir or Path(tempfile.mkdtemp(prefix="obi-rust-context-"))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    if args.generate_offsets:
        command = ["python3", str(REPO / "scripts/update-rust-offsets.py"), "--output", str(args.generate_offsets), "--work-dir", str(work), "--toolchains", ",".join(compilers)]
        if args.target:
            command += ["--targets", args.target]
        if args.offline:
            command += ["--offline"]
        for name in args.case or []:
            command += ["--case", name]
        subprocess.run(command, cwd=REPO, check=True)
        return
    if args.target or args.container and not args.live:
        parser.error("--target requires --generate-offsets; --container requires --live")
    cases = [case for case in versions["cases"] if (args.protocols or not case["name"].startswith("rustls-")) and (not args.case or case["name"] in args.case)]
    if not cases:
        parser.error("no selected fixtures (protocol fixtures require --protocols)")
    tests = Path(tempfile.mkdtemp(prefix="tests-", dir=work)) / "rust-context.test"
    command = ["go", "test", "-c", "-o", str(tests)]
    if args.live:
        command += ["-tags=privileged_tests"]
    command += ["./pkg/internal/ebpf/generictracer"]
    subprocess.run(command, cwd=REPO, env=dict(os.environ, CGO_ENABLED="0"), check=True)

    def run(binary, env, pattern, live=False, label=""):
        run_env = dict(os.environ, OBI_RUST_TEST_BINARY=str(binary), OBI_RUST_TLS_TEST_BINARY=str(binary))
        run_env.update({"OBI_RUST_TEST_"+key: value for key, value in env.items()})
        if live and run_env.get("OBI_RUST_TEST_INJECT"):
            run_env.setdefault("OBI_RUST_TEST_TPINJECTOR", "1")
        command = [str(tests), "-test.run=^("+pattern+")$", "-test.v", "-test.timeout=5m"]
        if live and args.container:
            command = ["docker", "run", "--rm", "--privileged", "--network", "none", "-v", "/sys:/sys", "-v", str(work)+":"+str(work)+":ro"] + [item for key, value in run_env.items() if key.startswith("OBI_RUST_TEST_") for item in ("-e", key+"="+value)] + [os.environ.get("OBI_RUST_RUNNER_IMAGE", RUNNER_IMAGE)] + command
        if live:
            evidence = work / "evidence" / compiler / tests.parent.name / (label+".log")
            evidence.parent.mkdir(parents=True, exist_ok=True)
            with evidence.open("w") as log:
                result = subprocess.run(command, cwd=REPO, env=run_env, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                print(evidence.read_text(), flush=True)
                raise subprocess.CalledProcessError(result.returncode, command)
            print(f"PASS {compiler}/{label}", flush=True)
        else:
            subprocess.run(command, cwd=REPO, env=run_env, check=True)

    for compiler in compilers:
        binaries = {}
        for case in cases:
            print(f"Building {compiler}/{case['name']}", flush=True)
            binary = build(case, work, compiler, offline=args.offline)
            snapshot = tests.parent / compiler / case["name"] / "rustcontext"
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(binary, snapshot)
            binary = snapshot
            subprocess.run(["strip", "--strip-debug", str(binary)], check=True)
            binaries[case["name"]] = binary
            expected = dict(case["env"], EXPECTED_COMPILER=compiler, EXPECTED_TOKIO=case["tokio"], EXPECTED_REQWEST=case["reqwest"])
            if case["hyper"]:
                expected["EXPECTED_HYPER"] = case["hyper"]
            run(binary, expected, "TestResolveRustBinary|TestRustProtocolLayouts|TestRustReleaseIdentity")
        def check_live(row):
            label, name, env = row
            print(f"Checking {compiler}/{label}", flush=True)
            run(binaries[name], env, "TestRustContextPropagation", live=True, label=label)
        if args.live and not args.fallbacks_only:
            selected = [row for row in scenarios(cases) if not args.scenario or row[0] in args.scenario]
            if not selected or args.scenario and set(args.scenario) - {row[0] for row in selected}:
                parser.error("unknown or empty live scenario selection")
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                list(pool.map(check_live, selected))
        if "latest" in binaries:
            stripped = binaries["latest"].with_name("rustcontext-stripped")
            shutil.copy2(binaries["latest"], stripped)
            subprocess.run(["strip", "--strip-all", str(stripped)], check=True)
            subprocess.run([str(tests), "-test.run=^TestRejectUnsupportedRustBinary$", "-test.v"], env=dict(os.environ, OBI_RUST_UNSUPPORTED_BINARY=str(stripped)), check=True)
        if (args.fallbacks or args.fallbacks_only) and args.live:
            variants = [("poll", "latest", {}), ("allocation", "latest", {}), ("channel", "latest", {}),
                        ("http1", "latest", {"INJECT":"1", "NO_USER_WRITE":"1"}),
                        ("h2-hpack", "rustls-client-http2", {"TLS":"1","H2":"1","INJECT":"1"}),
                        ("h2", "rustls-client-http1", {"TLS":"1","INJECT":"1"}),
                        ("tls-client-process", "rustls-direct-client-0.20", {"TLS":"1","RUSTLS_CLIENT":"1","INJECT":"1"}),
                        ("tls-server-process", "rustls-server-0.20", {"SERVER":"1","INJECT":"1"}),
                        ("channels-missing", "latest", {"PARTIAL_CLIENT":"1", "INJECT":"1", "NO_USER_WRITE":"1"}),
                        ("channels-missing-h2", "latest", {"PARTIAL_CLIENT":"1", "H2C":"1", "INJECT":"1", "NO_USER_WRITE":"1"}),
                        ("tasks-missing", "rustls-client-http1", {"TLS":"1","PARTIAL_CLIENT":"1"}),
                        ("tasks-missing-h2", "rustls-server-0.23", {"SERVER":"1","PARTIAL_CLIENT":"1"}),
                        ("h2-server", "rustls-server-0.23", {"SERVER":"1","PARTIAL_CLIENT":"1"})]
            def check_fallback(row):
                group, name, env = row
                if name not in binaries:
                    return
                binary = binaries[name].with_name("rustcontext-without-"+group)
                binary.unlink(missing_ok=True)
                print(f"Checking {compiler}/{name} without {group} hooks", flush=True)
                subprocess.run([str(tests), "-test.run=^TestPrepareRustAlternativeFixture$", "-test.v"], cwd=REPO,
                               env=dict(os.environ, OBI_RUST_TEST_BINARY=str(binaries[name]), OBI_RUST_STRIP_OUTPUT=str(binary), OBI_RUST_STRIP_GROUP=group), check=True)
                if not binary.exists():
                    print(f"SKIP {compiler}/{group}: no retained alternative in this build", flush=True)
                    return
                run(binary, env, "TestRustContextPropagation", live=True, label="without-"+group)
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                selected = [row for row in variants if not args.fallback_group or row[0] in args.fallback_group]
                if args.fallback_group and set(args.fallback_group) - {row[0] for row in selected}:
                    parser.error("unknown fallback hook group")
                list(pool.map(check_fallback, selected))


if __name__ == "__main__":
    main()
