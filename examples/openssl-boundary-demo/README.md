# OpenSSL trace propagation with OBI and Frida

This experimental example adds missing HTTP/1.1 trace context to a stock OpenSSL
CLI client and exports linked spans through OBI's existing OpenTelemetry pipeline.

| Service | What runs | What to observe |
| --- | --- | --- |
| `client` | `openssl s_client` from the nginx image | Sends requests over TLS with no `traceparent` header |
| `server` | nginx | Logs the received header and echoes it in the response |
| `obi` | The actual `bin/obi` executable | Discovers both processes and injects the header before encryption |
| `collector` | OpenTelemetry Collector | Prints the exported client and server spans |

Frida Core is a native library loaded by OBI. Its embedded JavaScript agent runs
inside the selected processes. No Python controller or Frida Server is used.

## Build the dependencies

Requirements: Linux amd64 with BTF, usable `bpf_probe_write_user`, Docker Compose,
and the Go version specified in the repository's `go.mod`. The OBI service uses
host PID visibility and elevated privileges to load eBPF and attach to processes.

From the repository root, build the pinned native dependency and OBI:

```sh
docker build -f examples/openssl-boundary-demo/Dockerfile.native \
  -t obi-frida-native-builder:17.24.3 .
mkdir -p bin/frida
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" \
  obi-frida-native-builder:17.24.3 \
  examples/openssl-boundary-demo/build-frida-core.sh /src/bin/frida amd64
make docker-generate
CGO_ENABLED=0 GOFLAGS=-tags=obi_frida make compile
```

Compose mounts `bin/obi` and `bin/frida/libfrida-core.so` read-only into the OBI
container. The Go build uses no CGO; the native dependency requires a C toolchain
to package. See the [runtime documentation](../../pkg/internal/frida/README.md)
for dependencies, ABI ownership, validation tools, and limitations.

## Run the Compose example

Start the applications before OBI to see the missing context:

```sh
docker compose -f examples/openssl-boundary-demo/compose.yaml up -d server client collector
docker compose -f examples/openssl-boundary-demo/compose.yaml top client
docker compose -f examples/openssl-boundary-demo/compose.yaml logs server
```

The process list contains `openssl s_client`. The literal request in
[compose.yaml](compose.yaml) is `GET / HTTP/1.1` with only a `Host` header.
Requests repeat every three seconds on the same connection. nginx initially logs
`traceparent=-` (its marker for a missing header).

Start OBI without restarting the applications:

```sh
docker compose -f examples/openssl-boundary-demo/compose.yaml up -d obi
docker compose -f examples/openssl-boundary-demo/compose.yaml logs -f obi server
```

OBI logs `Frida OpenSSL agent attached` for nginx and OpenSSL. After attachment,
nginx logs a header added before OpenSSL encrypted the request:

```text
received "GET / HTTP/1.1" traceparent=00-<trace-id>-<client-span-id>-01
```

The client logs also show this value echoed in the response. Inspect the spans:

```sh
docker compose -f examples/openssl-boundary-demo/compose.yaml logs collector
```

A `Client` span and a `Server` span share the header's trace ID. The server's
`Parent ID` equals the client's `ID` and the span ID in nginx's received header.
The [OBI configuration](compose/obi.yaml), [nginx configuration](compose/nginx.conf),
and [Collector configuration](compose/collector.yaml) supply the complete setup.

Stop the stack and remove its generated certificate:

```sh
docker compose -f examples/openssl-boundary-demo/compose.yaml down -v
```

## Scope

This is a controlled HTTP/1.1 proof of concept. It demonstrates propagation for
native OpenSSL callers with complete request headers in a supported write.
HTTP/2, QUIC, arbitrary TLS implementations, production overhead, and live arm64
execution remain outside the validated scope. Enabling Frida changes which engine
owns OpenSSL interception; attachment failures can leave selected TLS traffic
without Frida telemetry. See the runtime documentation before testing elsewhere.

`native-demo` and `native-fixture.c` are additional assertion tools for buffer
semantics and exported span ancestry. They are not services in this Compose stack.
