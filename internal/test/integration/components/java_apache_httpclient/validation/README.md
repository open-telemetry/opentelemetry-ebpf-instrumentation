# Apache HttpClient 4 propagation validation

This fixture uses an OBI-only Java source, an uninstrumented TLS HTTP/1.1 proxy,
and a standard OpenTelemetry downstream. TCP-option propagation is disabled.
The canonical transport suite checks headers recorded at the proxy, exact client
span identities, downstream parenting, and source ancestry through OBI INTERNAL
processing spans. It includes all execute overloads, pooling, reentrancy, reuse,
retry/redirect/authentication, supplied context, split/large headers, Expect
exclusions, connection/TLS/timeout/abort/write failures, and recovery.

## Reproduction

Build the agent and OBI through repository tooling:

```sh
make docker-generate
make java-docker-build
make compile
make testoutput
go test -v -count=1 -run '^TestJavaApacheHTTPClientTraceparent$' -timeout 20m ./internal/test/integration/
```

`JAVA_APACHE_RUNTIME_IMAGE` selects a digest-pinned JDK; CI runs JDK 8/11/17/21
on amd64 and arm64. Java compilation targets 8. The benchmark service uses JDK
HttpClient controls and therefore requires Java 11+.

For sustained measurements, build the fixture image and receiver/driver:

```sh
docker build -t obi-apache4-fixture -f internal/test/integration/components/java_apache_httpclient/Dockerfile .
mkdir -p internal/test/integration/components/java_apache_httpclient/validation/build
go build -o internal/test/integration/components/java_apache_httpclient/validation/build/harness internal/test/integration/components/java_apache_httpclient/validation/harness.go
python3 internal/test/integration/components/java_apache_httpclient/validation/run.py \
  --repo "$PWD" --binary "$PWD/bin/obi" --baseline /absolute/path/to/current-main-obi \
  --obi-image hatest-obi --output /absolute/path/to/evidence \
  --duration 120 --warmup 30 --rounds 3 --concurrency 32
```

Build the existing JDK traceparent fixture as `hatest-java-httpclient-traceparent`
for the downstream Java OpenTelemetry agent. The runner needs passwordless
`sudo bpftool` for reservation inspection and `jcmd` in the source image.
Its Docker objects carry a task-specific ownership label; cleanup verifies it.
The four CPU-set arguments select disjoint source, OBI, peer, and driver CPUs.
The defaults require eight logical CPUs. Use `--concurrency 128 --rounds 1` for
the higher-concurrency comparison; the source has 64 handlers, so this also
exercises queueing. Native capacity exhaustion is covered by inherited reservation
and lifecycle regressions rather than inferred from a concurrency-128 workload.

The runner alternates case order, creates fresh JVM/OBI processes per case,
warms before measurement, then drains exports and checks Java/native state.
Default cases compare current-main JDK sync with Apache propagation enabled and
disabled. TLS observation stays enabled in every case. `--cases final-sync`
also checks the shared-helper change against the same JDK control.

Each result records binary/tool hashes, runtime/image identity, workload and CPU
parameters, raw received headers and OTLP span records, latency, process CPU,
retained heap/direct buffers, Java tracking, and kernel slot/index occupancy.
Identity corruption is a hard failure. Missing headers/exports and parent-link
failures are reported independently; compare them with matched current-main
controls before attributing accepted bounded-LRU losses to Apache. OBI process
CPU excludes eBPF execution charged to application/network contexts. Separate
runs on a shared host cannot isolate propagation overhead or establish statistical
significance.

## Evidence status

Base: upstream main `1d6df6a4ce8db0de39c5924da14eb1bc20667013`, including #3798
and merge `549de846bb1ca2863590887ae2c8b156439008c9` from #3941.
The [validation evidence](../../../../../../devdocs/java-apache4-validation.md)
records the tested revisions, runtime matrix, measurements, and limitations.
Historical prototype results are not counted as current validation.
