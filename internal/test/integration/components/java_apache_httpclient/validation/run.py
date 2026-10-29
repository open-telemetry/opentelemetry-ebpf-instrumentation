# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import argparse
import collections
import gzip
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import threading
import time
import urllib.request

HERE = Path(__file__).resolve().parent
NAMES = ["obi3852-load-obi", "obi3852-load-app", "obi3852-load-downstream", "obi3852-load-peer"]
NETWORK = "obi3852-load"
TICKS = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")
CHECKS = (
    "ancestry_unverified_missing_server",
    "client_wrong_trace",
    "cyclic_ancestry",
    "downstream_parent_mismatch",
    "duplicate_client_exports",
    "duplicate_downstream_exports",
    "duplicate_header",
    "duplicate_source_servers",
    "duplicate_span_exports",
    "header_client_mismatch_with_export",
    "header_identity_unverified_missing_export",
    "invalid_header",
    "missing_ancestry_intermediate",
    "missing_client_export",
    "missing_downstream_export",
    "missing_header",
    "missing_header_with_expected_trace_client",
    "missing_header_with_wrong_trace_client",
    "missing_header_without_client_export",
    "missing_source_server",
    "source_client_parent_link_failure",
    "source_parent_mismatch",
    "source_wrong_trace",
    "unexpected_disabled_header",
    "wrong_protocol",
    "wrong_trace_header",
)


def command(*args, check=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(f"{args}: {result.stderr[-4000:]}")
    return result.stdout.strip()


def docker(*args):
    return command("docker", *args)


def http(path, port=28080):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/{path}", timeout=120) as response:
        return response.read().decode()


def bpf(*args):
    return json.loads(command("sudo", "-n", "bpftool", "-j", *args))


def process_stats(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()
    return {"user_s": int(fields[11]) / TICKS, "system_s": int(fields[12]) / TICKS,
            "rss_bytes": int(fields[21]) * PAGE, "threads": int(fields[17])}


def cleanup(output, label):
    for name in NAMES:
        result = command("docker", "inspect", name, check=False)
        containers = json.loads(result or "[]")
        if not containers:
            continue
        container = containers[0]
        if container["Config"].get("Labels", {}).get("obi.issue3852") != "load":
            raise RuntimeError(f"Refusing to remove unrelated container {name}")
        logs = subprocess.run(["docker", "logs", name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / f"{label}-{name}.log").write_bytes(logs.stdout)
        command("docker", "stop", "-t", "10", name, check=False)
        docker("rm", "-f", name)


def native_state(map_ids):
    maps = [m for m in bpf("map", "show") if m["id"] in map_ids and (m.get("name", "").startswith("java_http1") or m.get("name") == "ongoing_http")]
    result = []
    for m in maps:
        row = {k: m[k] for k in ["id", "name", "type", "max_entries", "bytes_memlock"] if k in m}
        if m["name"] == "ongoing_http":
            entries = bpf("map", "dump", "id", str(m["id"]))
            values = [entry.get("formatted", {}).get("value", {}) for entry in entries]
            known = all(isinstance(value, dict) and "java_http1_request_id" in value for value in values)
            row["java_write_scope_layout"] = "present" if known and values else "unavailable-or-empty"
            if known:
                row["active_java_write_scopes"] = sum(bool(value["java_http1_request_id"]) for value in values)
            result.append(row)
            continue
        if m["type"] == "hash":
            row["entries"] = len(bpf("map", "dump", "id", str(m["id"])))
        if m["type"] == "array" and m["max_entries"] == 10000:
            entries = bpf("map", "dump", "id", str(m["id"]))
            active = []
            for entry in entries:
                value = entry.get("formatted", {}).get("value")
                if isinstance(value, dict):
                    state = value["state"]
                else:
                    state = int.from_bytes(bytes(int(v, 16) for v in entry["value"][:8]), "little")
                if state:
                    active.append(state)
            row["active_slots"] = len(active)
            row["active_examples"] = active[:5]
        result.append(row)
    return result


def analyze(records, measured, enabled):
    counts = collections.Counter(dict.fromkeys(CHECKS, 0))
    counts["requests"] = len(measured)
    examples = {}

    def flag(name, bad, key, record):
        if bad:
            counts[name] += 1
            if len(examples.setdefault(name, [])) < 3:
                examples[name].append({"expected_trace": key, "record": record})

    for key, record in measured.items():
        spans = record["Spans"] or []
        source = [s for s in spans if s["Service"] == "perf-java-httpclient"]
        servers = [s for s in source if s["Kind"] == 2 and "/call/" in s["URL"]]
        clients = [s for s in source if s["Kind"] == 3 and "/backend/" in s["URL"]]
        downstream = [s for s in spans if s["Service"] == "perf-java-downstream" and s["Kind"] == 2]
        headers = record["Headers"]
        flag("wrong_protocol", record["Protocol"] != 1, key, record)
        flag("missing_source_server", not servers, key, record)
        flag("ancestry_unverified_missing_server", bool(clients) and not servers, key, record)
        flag("missing_client_export", not clients, key, record)
        flag("missing_downstream_export", not downstream, key, record)
        flag("duplicate_source_servers", len(servers) > 1, key, record)
        flag("duplicate_client_exports", len(clients) > 1, key, record)
        flag("duplicate_downstream_exports", len(downstream) > 1, key, record)
        identities = [(s["Trace"], s["ID"], s["Service"]) for s in spans]
        flag("duplicate_span_exports", len(identities) != len(set(identities)), key, record)
        flag("source_wrong_trace", any(s["Trace"] != key for s in servers), key, record)
        flag("source_parent_mismatch", any(s["Parent"] != key[16:] for s in servers), key, record)
        flag("client_wrong_trace", any(s["Trace"] != key for s in clients), key, record)
        ancestry = list(spans)
        for client in clients:
            ancestry += records.get(client["Trace"], {}).get("Spans") or []
        by_id = {(s["Trace"], s["ID"]): s for s in ancestry}
        expected = {(s["Trace"], s["ID"]) for s in servers}
        parent_bad = False
        missing_intermediate = False
        cyclic = False
        for client in clients:
            current = client
            seen = set()
            while True:
                parent = (current["Trace"], current["Parent"])
                if parent in expected:
                    break
                if parent in seen:
                    cyclic = True
                    parent_bad = True
                    break
                seen.add(parent)
                if not current["Parent"]:
                    parent_bad = True
                    break
                if parent not in by_id:
                    missing_intermediate = True
                    parent_bad = True
                    break
                current = by_id[parent]
        flag("source_client_parent_link_failure", bool(servers) and parent_bad, key, record)
        flag("missing_ancestry_intermediate", missing_intermediate, key, record)
        flag("cyclic_ancestry", cyclic, key, record)
        flag("unexpected_disabled_header", not enabled and bool(headers), key, record)
        if not enabled:
            continue
        flag("missing_header", not headers, key, record)
        flag("missing_header_without_client_export", not headers and not clients, key, record)
        flag("missing_header_with_wrong_trace_client", not headers and any(s["Trace"] != key for s in clients), key, record)
        flag("missing_header_with_expected_trace_client", not headers and any(s["Trace"] == key for s in clients), key, record)
        flag("duplicate_header", len(headers) > 1, key, record)
        if not headers:
            continue
        parts = headers[0].split("-")
        valid = (len(parts) == 4 and parts[0] == "00" and len(parts[1]) == 32 and len(parts[2]) == 16
                 and parts[1] != "0" * 32 and parts[2] != "0" * 16 and parts[3] == "01"
                 and all(c in "0123456789abcdef" for c in parts[1] + parts[2]))
        if valid:
            try:
                bytes.fromhex(parts[1] + parts[2])
            except ValueError:
                valid = False
        flag("invalid_header", not valid, key, record)
        if not valid:
            continue
        flag("wrong_trace_header", parts[1] != key, key, record)
        matching = any(s["Trace"] == parts[1] and s["ID"] == parts[2] for s in clients)
        flag("header_client_mismatch_with_export", bool(clients) and not matching, key, record)
        flag("header_identity_unverified_missing_export", not clients, key, record)
        flag("downstream_parent_mismatch", any(s["Trace"] != parts[1] or s["Parent"] != parts[2] for s in downstream), key, record)
    return {"counts": counts, "examples": examples,
            "negotiated_tls": collections.Counter(r["TLS"] for r in measured.values()),
            "negotiated_ciphers": collections.Counter(r["Cipher"] for r in measured.values()),
            "egress_connections": len({r["Connection"] for r in measured.values()})}


def run_case(args, label, binary, api, mode):
    cleanup(args.output, "previous")
    before_ids = {m["id"] for m in bpf("map", "show")}
    common = ["--label", "obi.issue3852=load", "--network", NETWORK]
    docker("run", "-d", "--name", NAMES[3], *common, "--network-alias", "peer", "--network-alias", "proxy",
           "--cpuset-cpus", args.cpu_sets[2], "-p", "28082:8082", "-p", "28317:4317", "-v", f"{HERE}:/load:ro",
           "--entrypoint", "/load/build/harness", args.image, "-role", "serve", "-cert", "/fixture/proxy.crt", "-key", "/fixture/proxy.key")
    docker("run", "-d", "--name", NAMES[2], *common, "--network-alias", "downstream", "--cpuset-cpus", args.cpu_sets[2],
           "-e", "OTEL_SERVICE_NAME=perf-java-downstream", "-e", "JAVA_TOOL_OPTIONS=-javaagent:/fixture/opentelemetry-javaagent.jar -Dsun.net.httpserver.nodelay=true -XX:ActiveProcessorCount=4",
           "-e", "OTEL_EXPORTER_OTLP_ENDPOINT=http://peer:4317", "-e", "OTEL_EXPORTER_OTLP_PROTOCOL=grpc",
           "-e", "OTEL_METRICS_EXPORTER=none", "-e", "OTEL_LOGS_EXPORTER=none", "-e", "OTEL_BSP_SCHEDULE_DELAY=100", args.downstream_image, "downstream")
    docker("run", "-d", "--name", NAMES[1], *common, "--cpuset-cpus", args.cpu_sets[0], "-p", "28080:8080",
           "-e", "OTEL_SERVICE_NAME=perf-java-httpclient", "-e", f"HTTPCLIENT_API={api}", "-v", f"{HERE}:/load:ro",
           "--entrypoint", "java", args.image, "-XX:ActiveProcessorCount=4", "-Xms512m", "-Xmx512m", "-XX:+UseG1GC",
           "-Dsun.net.httpserver.nodelay=true", "-Djavax.net.ssl.trustStore=/fixture/trust.p12",
           "-Djavax.net.ssl.trustStorePassword=changeit", "-cp", "/fixture/build/classes/java/main:/fixture/build/libs/*", "BenchmarkService")
    docker("run", "-d", "--name", NAMES[0], "--label", "obi.issue3852=load", "--network", "host", "--pid", "host", "--privileged",
           "--cpuset-cpus", args.cpu_sets[1], "-e", "GOMAXPROCS=4", "-e", f"JAVA_HTTPCLIENT_PROPAGATION={mode}",
           "-v", f"{binary}:/obi:ro", "-v", f"{HERE}/obi.yml:/load/obi.yml:ro",
           "-v", f"{args.repo}/internal/test/integration/system/sys/kernel/security_none:/sys/kernel/security:ro",
           "-v", "/sys/kernel/tracing:/sys/kernel/tracing:ro", "-v", "/sys/fs/cgroup:/sys/fs/cgroup", "--entrypoint", "/obi",
           args.obi_image, "--config=/load/obi.yml")
    for _ in range(90):
        try:
            health = json.loads(http("health"))
            if health["version"] and health["propagation"] == str(mode == "headers").lower():
                break
        except Exception:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("Java agent attachment/capability not ready")
    pids = {name: int(docker("inspect", container, "--format", "{{.State.Pid}}"))
            for name, container in zip(["obi", "app", "downstream", "peer"], NAMES)}
    map_ids = {m["id"] for m in bpf("map", "show")} - before_ids

    def load(duration):
        cmd = ["taskset", "-c", args.cpu_sets[3], str(HERE / "build/harness"), "-duration", f"{duration}s",
               "-concurrency", str(args.concurrency), "-size", str(args.size), "-rate", str(args.rate), "-url", "http://127.0.0.1:28080"]
        if mode == "headers":
            cmd.append("-enabled")
        return json.loads(command(*cmd))

    warm = load(args.warmup)
    old = set(json.loads(http("records", 28082)))
    before_jvm = json.loads(http("stats"))
    before = {name: process_stats(pid) for name, pid in pids.items()}
    peak = {name: value["rss_bytes"] for name, value in before.items()}
    finished = threading.Event()

    def sample():
        while not finished.wait(0.5):
            for name, pid in pids.items():
                peak[name] = max(peak[name], process_stats(pid)["rss_bytes"])

    sampler = threading.Thread(target=sample)
    sampler.start()
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.monotonic()
    try:
        measured = load(args.duration)
    finally:
        finished.set()
        sampler.join()
    wall = time.monotonic() - start
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    after = {name: process_stats(pid) for name, pid in pids.items()}
    after_jvm = json.loads(http("stats"))
    time.sleep(12)
    records = json.loads(http("records", 28082))
    selected = {key: record for key, record in records.items() if key not in old and record["Headers"] is not None}
    analysis = analyze(records, selected, mode == "headers")
    state = native_state(map_ids)
    java_state = http("state")
    outcomes = json.loads(http("outcomes"))
    if outcomes and outcomes[-1] != 0:
        raise RuntimeError(f"Apache execution scopes remain after drain: {outcomes[-1]}")
    docker("exec", NAMES[1], "jcmd", "1", "GC.run")
    time.sleep(0.5)
    retained_jvm = json.loads(http("stats"))
    metadata = {"label": label, "api": api, "mode": mode, "base_revision": "1d6df6a4ce8db0de39c5924da14eb1bc20667013",
                "implementation_revision": command("git", "-C", str(args.repo), "rev-parse", "HEAD"),
                "command": list(sys.argv), "cpu_sets": args.cpu_sets,
                "kernel": command("uname", "-srvm"), "machine": command("uname", "-m"),
                "tool_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.suffix in [".py", ".java", ".go", ".yml"]},
                "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "image": docker("image", "inspect", args.image, "--format", "{{.Id}}"), "health": health,
                "warmup": warm, "workload": measured, "correctness": analysis, "measurement_wall_s": wall,
                "before": before, "after": after, "peak_rss_bytes": peak, "jvm_before": before_jvm,
                "jvm_after": after_jvm, "jvm_after_requested_gc": retained_jvm,
                "java_state_after_drain": java_state, "apache_preparation_outcomes": outcomes, "native_state_after_drain": state,
                "export_drain_s": 12, "host_loadavg": Path("/proc/loadavg").read_text().strip(),
                "host_cpu_pressure": Path("/proc/pressure/cpu").read_text(),
                "driver_cpu_s": (usage_after.ru_utime + usage_after.ru_stime - usage_before.ru_utime - usage_before.ru_stime),
                "accounting_limits": "OBI process CPU excludes eBPF work charged elsewhere; live-thread allocation deltas are not valid allocation measurements; shared host; RSS includes committed memory."}
    for name in pids:
        cpu = sum(after[name][field] - before[name][field] for field in ["user_s", "system_s"])
        metadata[name + "_cpu_us_per_request"] = cpu * 1e6 / measured["requests"]
    with gzip.open(args.output / f"{label}-records.json.gz", "wb", compresslevel=1) as output:
        output.write(json.dumps(records, separators=(",", ":")).encode())
    (args.output / f"{label}.json").write_text(json.dumps(metadata, indent=2))
    print(json.dumps({"label": label, "requests": measured["requests"], "rps": measured["rps"],
                      "counts": analysis["counts"], "java_state": java_state, "native_state": state}), flush=True)
    if len(selected) != measured["requests"]:
        raise RuntimeError(f"Request/receiver count disagreement: {len(selected)} vs {measured['requests']}")
    cleanup(args.output, label)
    critical = ["wrong_trace_header", "invalid_header", "duplicate_header", "header_client_mismatch_with_export",
                "downstream_parent_mismatch", "cyclic_ancestry", "duplicate_span_exports"]
    failures = {name: analysis["counts"][name] for name in critical if analysis["counts"][name]}
    if failures:
        raise RuntimeError(f"Propagation identity corruption: {failures}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--image", default="obi-apache4-fixture")
    parser.add_argument("--downstream-image", default="hatest-java-httpclient-traceparent")
    parser.add_argument("--obi-image", default="hatest-obi-javaagent")
    parser.add_argument("--output", type=Path, default=HERE / "results")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--warmup", type=int, default=30)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--size", type=int, choices=[128, 1024, 8192], default=128)
    parser.add_argument("--rate", type=int, default=0)
    parser.add_argument("--cases", default="baseline-sync,final-apache4,final-apache4-disabled")
    parser.add_argument("--cpu-sets", nargs=4, default=["0,1", "2,3", "4,5", "6,7"],
                        metavar=("APP", "OBI", "PEER", "DRIVER"))
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    args.repo, args.binary, args.baseline, args.output = [p.resolve() for p in [args.repo, args.binary, args.baseline, args.output]]
    args.output.mkdir(parents=True, exist_ok=True)
    if args.pilot:
        args.duration, args.warmup, args.rounds = 10, 15, 1
    networks = json.loads(command("docker", "network", "inspect", NETWORK, check=False) or "[]")
    if not networks:
        docker("network", "create", "--label", "obi.issue3852=load", NETWORK)
    elif networks[0].get("Labels", {}).get("obi.issue3852") != "load":
        raise RuntimeError("Refusing to use an unrelated Docker network")
    variants = {"baseline-apache4": (args.baseline, "apache4", "headers"), "baseline-sync": (args.baseline, "sync", "headers"), "final-sync": (args.binary, "sync", "headers"),
                "final-async": (args.binary, "async", "headers"), "final-async-disabled": (args.binary, "async", "disabled"),
                "final-sync-disabled": (args.binary, "sync", "disabled"),
                "final-apache4": (args.binary, "apache4", "headers"), "final-apache4-disabled": (args.binary, "apache4", "disabled")}
    selected = args.cases.split(",")
    try:
        for round_id in range(1, args.rounds + 1):
            order = selected if round_id % 2 else list(reversed(selected))
            for name in order:
                label = f"{round_id}-{name}-c{args.concurrency}-s{args.size}-r{args.rate}"
                previous = args.output / f"{label}.json"
                if args.resume and previous.exists():
                    result = json.loads(previous.read_text())
                    binary, api, mode = variants[name]
                    if (result["binary_sha256"] != hashlib.sha256(binary.read_bytes()).hexdigest()
                            or result["api"] != api or result["mode"] != mode
                            or result["workload"]["duration_seconds"] < args.duration
                            or result["warmup"]["duration_seconds"] < args.warmup
                            or result["cpu_sets"] != args.cpu_sets
                            or not (args.output / f"{label}-records.json.gz").exists()):
                        raise RuntimeError(f"Completed result does not match the resumed workload: {label}")
                    print(f"Preserving completed measurement: {label}", flush=True)
                    continue
                run_case(args, label, *variants[name])
    finally:
        cleanup(args.output, "final")


if __name__ == "__main__":
    main()
