# Java HttpClient propagation load validation

This fixture uses an OBI-only JDK HttpClient source, an uninstrumented TLS
terminator, and a downstream instrumented by the checksum-pinned standard
OpenTelemetry Java agent in the parent Dockerfile. Incoming and outgoing
connections are pooled. Every incoming request has a distinct known context;
the application adds no outgoing context in the measured workload.

From the repository root, build the parent fixture image and compile the tools:

```sh
docker build -t hatest-java-httpclient-traceparent \
  -f internal/test/integration/components/java_httpclient_traceparent/Dockerfile .
go build -o internal/test/integration/components/java_httpclient_traceparent/load/harness \
  internal/test/integration/components/java_httpclient_traceparent/load/harness.go
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/internal/test/integration/components/java_httpclient_traceparent/load:/load" \
  -w /load --entrypoint javac hatest-java-httpclient-traceparent \
  --release 11 BenchmarkService.java
```

Build an OBI runtime image with the canonical
`internal/test/integration/components/obi/Dockerfile-with-javaagent`, tagged
`hatest-obi-javaagent`. Build the baseline binary from
`dcb3f3dda1c23845530299be7f9fedb80071f404`, with generated artifacts produced by
repository tooling. Use the same `CGO_ENABLED=0`, architecture, and build flags
for the baseline and final binaries. Then run:

```sh
python3 internal/test/integration/components/java_httpclient_traceparent/load/run.py \
  --binary /absolute/path/to/final/obi --baseline /absolute/path/to/baseline/obi \
  --output /absolute/path/to/evidence --duration 120 --warmup 30 --rounds 3 \
  --concurrency 32
```

The runner requires Linux, Docker, passwordless `sudo bpftool`, `taskset`, and
eight available CPUs by default. `--cpu-sets APP OBI PEER DRIVER` overrides CPU
placement. It reserves ports 28080, 28082, and 24317 and containers labelled
`obi.issue3855=load`. Run without another OBI process instrumenting this source.
It refuses to replace unrelated containers or networks. `--pilot` provides a
short fixture check, which is insufficient for performance conclusions.
`--resume` preserves completed measurements after checking the binary,
API, propagation mode, durations, CPU placement, and raw-record artifact.
Raw-record compression runs outside the timed workload interval.

Each round compares baseline synchronous, final synchronous, final asynchronous,
and final asynchronous with header propagation disabled. TLS tracing stays on.
Even rounds reverse the order. `--cases`, `--concurrency`, `--rate`, and `--size`
select additional controls. The source has 64 handler threads, so concurrency
above 64 also exercises the incoming queue.

The JSON reports distinguish header errors, missing exports, identity
mismatches, ancestry through INTERNAL spans, downstream parents, duplicate
exports, connection reuse, and HTTP results. Raw receiver records are compressed
separately. Missing exports remain failures to verify ancestry or identity;
they are never counted as successful correlations. Warmup is excluded.

After a 12-second export drain, Java identity-map and reservation counters are
recorded separately from the tracer's kernel maps. A preallocated array has
10,000 entries even when its occupied-slot count is zero. The connection index
is a hash map whose actual entries are counted. Retained JVM memory is sampled
after a requested full GC outside the measurement interval.

Process CPU covers user and system time for the application and OBI separately.
OBI process CPU excludes eBPF work charged elsewhere. RSS includes committed
memory; live-thread allocation counters are not total allocation measurements.
The shared host, export collector, downstream, JIT, and closed-loop queueing
limit comparisons. Inspect paired runs and raw error examples before drawing
performance or correctness conclusions.

To test the startup agent without an OBI kernel control path, run this from
the repository root:

```sh
python3 internal/test/integration/components/java_httpclient_traceparent/load/native_unavailable.py
```

It uses the generated embedded JAR, checks successful HTTPS
requests before and after a connection failure, verifies no injected header,
and requires Java tracking to drain. It reserves the parent fixture's ports;
run it separately from the transport suite and any OBI tracer.

The transport suite's `tracking-capacity` case fills the Java identity map
using one synthetic unfinished transport, then sends a real HTTPS request.
It verifies fail-open behavior and successful propagation after cleanup.
This exercises the Java limit without opening 10,000 TLS connections; it does
not simulate 10,000 occupied kernel reservations. Privileged `TestJavaHTTP1*`
tests exercise kernel capacity and request-ID ownership separately.
