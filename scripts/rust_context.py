# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Shared release fixture construction for Rust offsets and integration tests."""

import json
import fcntl
import os
from contextlib import contextmanager
from pathlib import Path
import shutil
import subprocess
import tempfile


REPO = Path(__file__).resolve().parent.parent
VERSIONS = REPO / "configs/offsets/rust_versions.json"
FIXTURE = REPO / "internal/test/integration/components/rustcontext"


def load_versions():
    return json.loads(VERSIONS.read_text())


def prepare(case, project):
    project.mkdir(parents=True, exist_ok=True)
    shutil.copytree(FIXTURE / "src", project / "src", dirs_exist_ok=True)
    manifest = (FIXTURE / "Cargo.toml").read_text()
    manifest = manifest.replace("=1.54.1", "=" + case["tokio"])
    manifest = manifest.replace("=0.13.5", "=" + case["reqwest"])
    if not case["reqwest"].startswith("0.13."):
        manifest = manifest.replace('tls = ["reqwest/rustls", "reqwest/http2"]', 'tls = []')
    if case["reqwest"].startswith(("0.10.", "0.11.")):
        manifest = manifest.replace('default-features = false, features = ["http2"]', 'default-features = false')
    hyper = 'hyper = { version = "=1.12.0", features = ["client", "http1"] }'
    manifest = manifest.replace(hyper, hyper.replace("1.12.0", case["hyper"]) if case["hyper"] else "")
    if not case["hyper"]:
        manifest = "\n".join('server = []' if line.startswith('server = ') else
                             'rustls_client = []' if line.startswith('rustls_client = ') else
                             line for line in manifest.splitlines())
    if case["reqwest"].startswith("0.10."):
        manifest = manifest.replace("[dependencies]", '[dependencies]\ntokio02 = { package = "tokio", version = "=0.2.25", features = ["full"] }')
    manifest = manifest.replace("=0.26.6", "=" + case.get("tokio_rustls", "0.26.6"))
    path = project / "Cargo.toml"
    if not path.exists() or path.read_text() != manifest:
        path.write_text(manifest)
        (project / "Cargo.lock").unlink(missing_ok=True)
    return path


def prepare_dependencies(case, project, toolchain, offline=False, refresh_lock=False):
    manifest = prepare(case, project)
    if refresh_lock or not (project / "Cargo.lock").exists():
        command = ["cargo", "+"+toolchain, "generate-lockfile", "--manifest-path", str(manifest)]
        if offline:
            command.append("--offline")
        subprocess.run(command, cwd=REPO, check=True)
    return manifest


@contextmanager
def build_lock(work):
    lock = work / "target" / ".obi-rust-build.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        yield


def build(case, work, toolchain, target=None, offsets=False, offline=False, refresh_lock=False):
    with build_lock(work):
        return build_unlocked(case, work, toolchain, target, offsets, offline, refresh_lock)


def build_unlocked(case, work, toolchain, target=None, offsets=False, offline=False, refresh_lock=False):
    if target is None:
        target = "aarch64-unknown-linux-gnu" if os.uname().machine in ("aarch64", "arm64") else "x86_64-unknown-linux-gnu"
    project = work / toolchain / case["name"]
    manifest = prepare_dependencies(case, project, toolchain, offline, refresh_lock)
    command = ["cargo", "+" + toolchain, "build", "--manifest-path", str(manifest),
               "--target-dir", str(work / "target"), "--locked"]
    if case["features"]:
        command.append("--features=" + case["features"])
    if target:
        command.append("--target=" + target)
    if offline:
        command.append("--offline")
    if not offsets:
        command.append("--release")
    env = dict(os.environ)
    if target == "aarch64-unknown-linux-gnu" and os.uname().machine != "aarch64":
        env.setdefault("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", "aarch64-linux-gnu-gcc")
        env.setdefault("CC_aarch64_unknown_linux_gnu", "aarch64-linux-gnu-gcc")
    subprocess.run(command, cwd=REPO, env=env, check=True)
    output = work / "target"
    if target:
        output /= target
    output /= "debug" if offsets else "release"
    output /= "rustcontext"
    binary = project / target / ("offsets" if offsets else "release") / "rustcontext"
    binary.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".rustcontext-", dir=binary.parent)
    os.close(descriptor)
    try:
        shutil.copy2(output, temporary)
        os.replace(temporary, binary)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return binary


def scenarios(cases):
    for case in cases:
        yield case["name"], case["name"], case["env"]
    names = {case["name"] for case in cases}
    for name in ("latest", "reqwest-0.12", "reqwest-0.11", "reqwest-0.10"):
        if name in names:
            yield name + "-h2c", name, {"H2C": "1", "INJECT": "1"}
            yield name + "-socket-http1", name, {"INJECT": "1", "NO_USER_WRITE": "1"}
            yield name + "-socket-http2", name, {"H2C": "1", "INJECT": "1", "NO_USER_WRITE": "1"}
    if "latest" in names:
        yield "latest-owned-http1", "latest", {"INJECT": "1"}
        yield "latest-grouped-worker", "latest", {"INJECT": "1", "SHARED_EXECUTABLE": "1"}
        yield "latest-split-http1", "latest", {"INJECT": "1", "SPLIT_HEADER": "1"}
        yield "latest-forwarded-http1", "latest", {"INJECT": "1", "APP_HEADER": "1", "FORWARDED_APP_HEADER": "1"}
        yield "latest-forwarded-http2", "latest", {"H2C": "1", "INJECT": "1", "APP_HEADER": "1", "FORWARDED_APP_HEADER": "1"}
        yield "latest-http1-otel-exporter", "latest", {"INJECT": "1", "OTEL_EXPORTER": "1"}
        yield "latest-http2-otel-exporter", "latest", {"H2C": "1", "INJECT": "1", "OTEL_EXPORTER": "1"}
        yield "latest-http1-otel-exporter-app-header", "latest", {"INJECT": "1", "OTEL_EXPORTER": "1", "APP_HEADER": "1", "FORWARDED_APP_HEADER": "1"}
        yield "latest-http2-otel-exporter-app-header", "latest", {"H2C": "1", "INJECT": "1", "OTEL_EXPORTER": "1", "APP_HEADER": "1", "FORWARDED_APP_HEADER": "1"}
    for name in ("rustls-client-http1", "rustls-client-http2"):
        if name in names:
            env = {"TLS": "1", "INJECT": "1", "OTEL_EXPORTER": "1"}
            if name.endswith("http2"):
                env["H2"] = "1"
            yield name+"-otel-exporter", name, env
    for name, env in (("latest", {"H2C": "1", "INJECT": "1", "APP_HEADER": "1"}),
                      ("rustls-client-http1", {"TLS": "1", "INJECT": "1", "APP_HEADER": "1"})):
        if name in names:
            yield name + "-app-header", name, env

    if "rustls-server-0.23" in names:
        yield "rustls-server-http1", "rustls-server-0.23", {"SERVER":"1", "SERVER_HTTP1":"1", "INJECT":"1"}
        yield "rustls-server-http1-trailers", "rustls-server-0.23", {"SERVER":"1", "SERVER_HTTP1":"1", "INJECT":"1", "TRAILERS":"1"}
        yield "rustls-server-http1-trailers-socket", "rustls-server-0.23", {"SERVER":"1", "SERVER_HTTP1":"1", "INJECT":"1", "TRAILERS":"1", "NO_USER_WRITE":"1"}
        for sampler, parent_flags, sampled in (("always_off", "01", "0"),
                                                ("always_on", "00", "1"),
                                                ("parentbased_always_off", "01", "1"),
                                                ("parentbased_always_on", "00", "0")):
            yield "rustls-server-"+sampler, "rustls-server-0.23", {
                "SERVER": "1", "TLS": "1", "H2": "1", "INJECT": "1",
                "SAMPLER": sampler, "PARENT_FLAGS": parent_flags, "EXPECTED_SAMPLED": sampled,
            }
    for name in sorted(names):
        if name.startswith("rustls-direct-client-"):
            yield name+"-http2", name, {"TLS":"1", "H2":"1", "RUSTLS_CLIENT":"1", "INJECT":"1"}
