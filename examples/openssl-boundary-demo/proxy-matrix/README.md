# Proxy propagation matrix

This example measures the current Frida OpenSSL PoC through real nginx and Apache
proxies. It separates three questions: did the request succeed, did its trace
context reach the destination, and did the Collector receive the correct parent
edges through every instrumented HTTP hop?

See [measured support and required work](support.md) for the results. The matrix
does not change the instrumentation to make a scenario pass.

## Build

Use a Linux amd64 host satisfying the [parent example's requirements](../README.md#build-the-dependencies).
Build `bin/obi` with `CGO_ENABLED=0` and `obi_frida`, and package
`bin/frida/libfrida-core.so` using those instructions first. Docker Compose 2.24.4
or newer is needed for `!override`. The host needs `openssl s_client` and a curl
with HTTP/2 support (`curl -V`). Tested host clients were OpenSSL 3.0.13 and curl
8.5.0 with nghttp2.

From the repository root:

```sh
CGO_ENABLED=0 go build -o bin/frida-proxy-matrix ./examples/openssl-boundary-demo/proxy-matrix
```

For the two HTTP/3 cases, build the separate native **test client**. Its source
archives and base image are checksum-pinned in [Dockerfile.http3](Dockerfile.http3).
It uses curl, ngtcp2, nghttp3 and OpenSSL 3.5; it is not a new OBI dependency.
The Go controller and OBI still use no CGO or Python.

```sh
docker build -f examples/openssl-boundary-demo/proxy-matrix/Dockerfile.http3 \
  -t obi-frida-proxy-http3:local .
mkdir -p bin/frida-http3
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/bin:/out" \
  --entrypoint cp obi-frida-proxy-http3:local -r /opt/h3/. /out/frida-http3/
LD_LIBRARY_PATH="$PWD/bin/frida-http3/lib" bin/frida-http3/bin/curl -V
```

The last command must list HTTP3. Requests use `--http3-only`, so a successful
HTTP/1 or HTTP/2 fallback cannot be mistaken for HTTP/3 coverage. See curl's
[HTTP/3 build documentation](https://curl.se/docs/http3.html).

## Run

Run the entire matrix twice to compare Frida with the existing socket-header
propagation setting:

```sh
bin/frida-proxy-matrix --output testoutput/proxy-disabled
bin/frida-proxy-matrix --propagation headers --output testoutput/proxy-headers
```

Each output directory must be new. Run the commands sequentially: two OBI
instances attaching to the same processes would invalidate the experiment.
Alternatively run selected cases without building the HTTP/3 client:

```sh
bin/frida-proxy-matrix \
  --cases direct-tls,nginx-tls-passthrough,apache-connect,nginx-tls-to-tls \
  --output testoutput/proxy-small
```

The Go runner creates certificates, starts [Compose](compose.yaml), waits for OBI
to attach, sends requests using native clients, reads backend responses and proxy
logs, and verifies exported OTLP spans. No application tracing SDK is installed.
curl reads its options from stdin after attachment; OpenSSL receives its HTTP
request after attachment. This deliberately excludes attachment races from the
protocol experiment.

Ports bind to loopback with dynamically assigned host ports. The generated
certificate and the public `matrix:matrix` proxy credentials are test fixtures.
OBI has privileged access and host PID visibility. The unobserved proxy's process
arguments intentionally do not match OBI's selector; all other application
processes are selected, including Apache's worker.

The runner removes its own Compose project and volumes after collecting the
results, including on failure. It leaves the original example stack alone. Use
`--keep` to inspect a running stack; the final connection-drain pass is then
skipped. To inspect or remove a retained stack, substitute its actual output path:

```sh
export MATRIX_ARTIFACTS="$PWD/testoutput/proxy-small"
export MATRIX_UID="$(id -u)" MATRIX_GID="$(id -g)"
docker compose -p obi-frida-proxy-matrix \
  -f examples/openssl-boundary-demo/proxy-matrix/compose.yaml logs nginx apache
docker compose -p obi-frida-proxy-matrix \
  -f examples/openssl-boundary-demo/proxy-matrix/compose.yaml down -v
```

## Read the evidence

`results.json` contains each case's backend responses, proxy events and exported
spans, along with:

| Field | Meaning |
| --- | --- |
| `scenario_proven` | The advertised condition occurred: for example HTTP/3 ingress, one reused upstream connection, both load-balanced origins, 503 followed by 200, cache MISS/HIT, or successful client-certificate verification |
| `context_continues` | The destination received the originating client's trace ID; for existing-header cases, the supplied header was preserved exactly |
| `full_ancestry` | Client → each instrumented proxy's server and outgoing client spans → origin server, with correct trace IDs and parent IDs; internal processing spans may intervene |
| `support` | Combined classification; a shared trace ID alone is `context-only` |
| `required_work` | The next implementation or policy work needed for the measured gap |
| `spans_before_drain` | Matching span count before the final snapshot, to expose delayed export |
| `reported_target` | Original URL attribute before normalization, useful for absolute-form forward-proxy requests |

The intentionally unobserved reverse proxy requires only client → origin linkage,
not spans for that unselected process. A cache HIT requires client → proxy server
linkage and no origin request. Existing caller context is checked independently
of whether OBI adopts that context for its own client span.

Requests must return HTTP 200. Authentication also requires an unauthenticated
CONNECT to return 407; the HTTP/2 and HTTP/3 cases must appear with that protocol
in the frontend access log. Pooling, retry, cache and load-balance conditions have
explicit assertions. Transport errors and unproven fixture conditions are
`harness-error` and exit nonzero. Measured instrumentation gaps are results, so
the runner can finish and report all cases; exit zero does **not** mean all cases
are supported.

After per-case export waits, the runner stops the applications while leaving OBI
and the Collector running, waits three seconds, and reevaluates against the final
span snapshot. This accounts for connection-lifetime export delays; it does not
establish bounded export latency during a long-running service. Intermediate
console classifications are provisional; use the final JSON.

Raw `traces.jsonl`, OBI, Collector, proxy and client logs remain in the output
directory. Raw telemetry can contain host resource attributes; inspect it before
sharing. The checked-in support report contains only fixture evidence.

## Validation and limits

```sh
CGO_ENABLED=0 go test ./examples/openssl-boundary-demo/proxy-matrix
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -o bin/frida-proxy-matrix-arm64 ./examples/openssl-boundary-demo/proxy-matrix
```

The analyzer tests reject the misleading case where all spans share a trace ID
but the origin bypasses the proxy's outgoing span. Live matrix results are Linux
amd64 only; an arm64 build does not establish live arm64 compatibility. The
original native buffer/retry/shutdown fixture remains unchanged.

This is representative coverage, not certification of arbitrary proxies. It does
not yet cover WebSocket/gRPC streaming, HTTP/2 multiplexing and flow control,
SOCKS, redirects, URL-rewrite policies, connection-failure retries, service-mesh TLS libraries, fork or
library-reload races, or production load and fault recovery. The large-body case
tests transport/header handling, not backend body integrity: nginx returns a
header echo without validating the body. See the support report for the separate
application-write versus TLS-record fragmentation results.
