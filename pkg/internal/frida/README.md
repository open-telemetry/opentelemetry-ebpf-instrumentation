# Experimental Frida OpenSSL runtime

OBI can own Frida attachment, OpenSSL interception, trace-context creation, and span export.
The Go binary embeds the JavaScript agent and calls Frida Core directly through
[`purego`](https://github.com/ebitengine/purego), without CGO or a Python controller.
Discovery selects processes; Go owns attachment, messages, RPC, and shutdown.
The native Frida engine still runs in OBI and injects its runtime into each target.

For the readable end-to-end example, start with the
[Docker Compose walkthrough](../../../examples/openssl-boundary-demo/README.md#run-the-compose-example).
It uses the real OBI binary, an OpenSSL CLI client, nginx, and an OpenTelemetry Collector.

Enable this optional backend through Config v2:

```yaml
extensions:
  obi:
    version: "2.0"
    capture:
      runtimes:
        frida:
          enabled: true
          library: /opt/obi-frida/libfrida-core.so
```

Add these settings to a complete OBI configuration with capture rules and an exporter.
Supply a Frida Core **17.24.3** shared library built as described below.
The library path is required; no package is downloaded during OBI startup.
Build OBI with `CGO_ENABLED=0` and the opt-in `obi_frida` tag.
Without that tag, the default build retains its existing static-link behavior.
The tagged binary uses the system dynamic loader even when this runtime is disabled.
There is no Config v1 setting or Python runtime setting.

## Ownership and data flow

Frida owns the OpenSSL interception points while this backend is enabled and supported.
OBI omits its OpenSSL and .NET OpenSSL wrapper uprobes to avoid duplicate interception.
A live experiment found that Frida rejected OpenSSL entry points with existing OBI uprobes.
Other processes using uprobes on the same library can also prevent Frida attachment.

The [agent](agent.js) hooks `SSL_write`, `SSL_write_ex`, `SSL_write_ex2`, `SSL_read`, and `SSL_read_ex`.
Per-thread nesting suppresses duplicate wrapper observations.
`SSL_get_fd` and Frida socket inspection supply the connection addresses.
Socket-backed IPv4 and IPv6 connections are supported by the bridge.

Before encrypting an eligible request, the agent allocates replacement storage and requests context synchronously through OBI's ioctl probe.
The [context bridge](../../../bpf/generictracer/frida.h) uses OBI's existing connection-aware parent lookup and trace-ID generation.
It returns the context with `bpf_probe_write_user` into an agent-owned control buffer.
The application input remains unchanged, including readonly inputs.

The context map keys each replacement buffer by host PID and checks the process start time before adoption.
Successful TLS operations enter OBI's [protocol pipeline](../../../bpf/generictracer/frida_tls.h) through a separate ioctl message.
The HTTP client parser adopts that exact context instead of generating another client span ID.
The TLS server parser reads the incoming header when this backend is active.
This gives incoming TLS headers precedence over existing socket context across the generic tracer.
Existing SSL exclusion from socket header injection remains in place.

The agent reports successful wire-byte counts to the parser.
It translates expanded writes back into application-byte counts before returning to the caller.
Replacement pointers and lengths remain stable across unsuccessful nonblocking retries, including OpenSSL's moving-buffer mode.
A successful partial write releases replacement state so the application can change its unsent bytes.
Short HTTP response prefixes accumulate until their status code is available.
Failed operations provide no successful plaintext bytes.

The ioctl ABI is internal to the embedded agent and BPF program shipped together.
Command `0x0b10f1` requests or cancels context with a 104-byte control block.
Command `0x0b10f2` reports a connection, buffer pointer, successful length, and direction in a 56-byte control block.
User pointers and lengths are checked before protocol parsing.
These commands use OBI's PID filter and require the enabled BPF constant.

## Supported boundaries

- Linux processes with 64-bit x64 or arm64 OpenSSL APIs and socket-backed BIOs.
- Exported OpenSSL entry points; hidden static symbols are unsupported.
- Complete HTTP/1.1 request headers within the first 8192 bytes of one write.
- Requests of at most 1 MiB minus the inserted 70-byte header.
- `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, and `OPTIONS` requests.
- Existing `traceparent` headers are preserved without adding another header.
- Partial-write injection requires the original headers and inserted header to fit within the first 512-byte record.
- Custom split-fragment settings and legacy one-byte record splitting are unsupported.
- At most 256 expanded requests remain pending per attached process.

Split headers, upgrades, CONNECT, HTTP/2, QUIC, memory BIOs, and alternative TLS libraries receive no header insertion.
Socket-backed TLS plaintext still reaches OBI's existing parsers when insertion is skipped.
Existing headers retain OBI's usual semantics; their span ID may belong to an application tracer instead of OBI's client span.

Go and Java retain their existing runtime agents.
Their native OpenSSL calls are outside this Frida backend.
Frida sessions do not automatically follow a fork; discovery must select the child process.
Library unload/reload, arbitrary pipelining, asynchronous completion APIs, and concurrent operations on one SSL object remain unvalidated.
The application must obey OpenSSL's retry pointer and length contract.

The context handshake requires `CAP_SYS_ADMIN`, usable `bpf_probe_write_user`, and a kernel without restrictive lockdown.
Frida attachment also requires permission to instrument the selected process.
Target syscall policies must permit the marker ioctl calls.
When kernel support is unavailable, OBI retains its normal OpenSSL uprobes.
A missing dependency or attachment failure is logged; selected socket-backed TLS traffic then lacks Frida telemetry.
The backend does not switch interception engines during an active process session.

## Lifecycle

Attachments use stable process handles and validate start times before loading the agent.
The shared runtime injection queue serializes attachment with Java's process-wide credential changes.
Deselection cancels queued work and stops only the matching process incarnation.
Process termination closes its controller session.

Graceful shutdown disables new header expansion before removing hooks.
If an expanded write still needs retries, the controller eternalizes its script to preserve the required buffer.
That script removes hooks after the pending operations finish or their SSL objects are freed.
Frida's runtime may remain resident until process exit.
An abrupt OBI crash cannot provide the same graceful-draining guarantee.

## Native library packaging

The official Core devkit contains a static archive, not the shared library needed by `purego`.
[build-frida-core.sh](../../../examples/openssl-boundary-demo/build-frida-core.sh)
verifies the official archive's pinned SHA-256 and links the archive into `libfrida-core.so`.
It preserves the Frida and namespaced GLib symbols used by the binding.
It writes `SHA256SUMS` and a manifest containing the source digest, compiler, ELF dependencies, and symbol versions.
Two independent builds with the supplied amd64 container produced identical library bytes.
The script has pinned devkits for Linux amd64 and arm64; `CC` may select a target compiler.
Building the native dependency requires a C toolchain; **building OBI does not use CGO**.

For a repeatable Linux amd64 toolchain, use the supplied container recipe:

```sh
docker build -f examples/openssl-boundary-demo/Dockerfile.native \
  -t obi-frida-native-builder:17.24.3 .
mkdir -p bin/frida
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" \
  obi-frida-native-builder:17.24.3 \
  examples/openssl-boundary-demo/build-frida-core.sh /src/bin/frida amd64
```

The Dockerfile pins Ubuntu by image digest, bootstraps certificates from a checksum-pinned package,
and installs build dependencies from the fixed `20261020T000000Z` Ubuntu snapshot.
The script can also run directly on a suitable glibc host with a compiler, curl, binutils, tar, and xz.
Identical inputs/toolchains are required for reproducible output; a different host compiler is recorded in the manifest.
No Frida source rewrite or custom C API shim is required.

Ship the resulting library with OBI and retain Frida's applicable license notices.
For this amd64 build, runtime dependencies are glibc, libm, libgcc_s, and the ELF loader;
GLib and Frida's other bundled engine dependencies are inside the devkit archive.
The inspected library requires GLIBC symbols through **2.38**; Ubuntu 24.04 was tested.
A C compiler, development headers, Python, and Node.js are unnecessary at runtime.
Musl/Alpine, older glibc distributions, and the standard OBI container images are not validated packaging targets.
Use `readelf -d` and `readelf --version-info` on each packaged architecture instead of assuming the amd64 dependency floor applies.

## Native ABI and lifecycle

[core/native.go](core/native.go) binds only initialization/versioning, local device lookup,
attachment, script creation/loading/posting/unloading/eternalization, signals, cancellation, and object cleanup.
Pointers are opaque native handles; C `gboolean`/enum values use 32-bit integers, and `GError` has its explicit native layout.
Signal callbacks copy borrowed message strings before returning.
Two process-wide callback trampolines route integer user-data IDs through a Go registry;
C never retains a Go object pointer, and attaching more processes does not allocate more callback trampolines.
Callbacks enqueue messages without blocking on script RPC or native teardown.

Frida initializes its own internal context/thread.
A separate GLib default loop, run on a locked Go OS thread, dispatches script messages and session-detached signals.
Synchronous API calls run outside callbacks; a native `GCancellable` connects them to Go cancellation.
The cancellation callback finishes before its native object is unreferenced.
Shutdown disconnects signals, releases scripts/sessions/device/manager references, joins the signal loop,
and calls Frida shutdown/deinitialization after all sessions finish.

The minimal feasibility experiment attached to a controlled `sleep` child, loaded a script,
received immediate and delayed messages, performed RPC, unloaded, and detached.
The checked-in live test repeats attachment twelve times with forced Go garbage collection,
then exercises invalid scripts, RPC errors, cancellation, and target exit.
An initial experiment calling `dlclose` after successful shutdown exited with SIGSEGV (139).
Keeping the library mapped eliminated that exit fault in repeated runs.
Consequently the prototype retains its library mapping until process exit and supports one engine lifetime per process;
it does not promise unload/reinitialize support.
The binding intentionally depends on this pinned devkit ABI, including its namespaced GLib exports;
upgrading Frida or purego requires repeating the native lifecycle tests.

Run the feasibility test without root against its own controlled child:

```sh
CGO_ENABLED=0 OBI_FRIDA_LIBRARY="$PWD/bin/frida/libfrida-core.so" \
  go test -tags=obi_frida -v -count=1 ./pkg/internal/frida/core
```

## Advanced integration assertions without Python

Build OBI, the Go runner, and the controlled native OpenSSL fixture:

```sh
CGO_ENABLED=0 GOFLAGS=-tags=obi_frida make compile
CGO_ENABLED=0 go build -o bin/frida-native-demo ./examples/openssl-boundary-demo/native-demo
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" \
  obi-frida-native-builder:17.24.3 \
  cc -Wall -Wextra -Werror -O0 -g examples/openssl-boundary-demo/native-fixture.c \
  -o bin/openssl-native-fixture -lssl -lcrypto -ldl
sudo bin/frida-native-demo --obi "$PWD/bin/obi" \
  --fixture "$PWD/bin/openssl-native-fixture" --library "$PWD/bin/frida/libfrida-core.so"
```

The runner creates a temporary trusted localhost certificate, starts two native OpenSSL processes,
and lets OBI discover/attach to them. A local OTLP receiver verifies incoming server ancestry,
unique outgoing client spans, exact downstream server parents, HTTP status, and endpoint ports.
It checks readonly original storage, existing headers, short/split reads, fragmented requests,
opaque input, partial counts, edits to unsent body bytes, and moving-buffer retries.
Temporary files and controlled processes are cleaned up on success or assertion failure.
No Python controller, interpreter, or Frida Server participates in this demonstration.

Append `--drain` to stop OBI during a pending retry and verify that the application finishes its original write.
Telemetry after OBI stops is outside that assertion.
OpenSSL 3.5 additionally exercises direct `SSL_write_ex2` and nested `_ex` wrappers;
`--openssl-library-dir /path/to/openssl/lib64` selects alternate libraries for the fixture processes only.

For Linux arm64 compilation:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags=obi_frida -o bin/obi-arm64 ./cmd/obi
```

This compilation check does not execute callbacks or inject a runtime on arm64.
Build the arm64 shared library with the script on an arm64 glibc host (or a suitable cross compiler)
and repeat the live tests before deploying it.

## Verified results

Native-controller validation used Linux amd64, kernel `7.0.0-1014-aws`, Frida 17.24.3, purego 0.11.1, Go 1.27.2, and LLVM 22.

| Check | Result |
| --- | --- |
| OpenSSL 3.0.13 | Eight cases; full OTLP ancestry, unique client/server observations, status codes, and endpoint ports passed |
| OpenSSL 3.5.0 | Nine cases passed, including direct `SSL_write_ex2` and nested wrappers |
| Partial writes | Caller counts and subsequent edits to unsent body bytes reached the peer correctly |
| Moving-buffer retries | Replacement storage remained stable while caller retry buffers moved |
| Graceful shutdown | OBI stopped with a pending write; the application completed its original request correctly |
| IPv6 loopback | Previous-controller integration passed; the native Go demo currently uses IPv4 |
| Disabled feature | Default static build and tagged build require no installed Python |
| Build | CGO-free tagged OBI and native ABI test compile for amd64 and arm64; default build remains static |
| Kernel verifier | Debug on/off and bounded/unlimited transaction variants passed |
| Go validation | Affected packages pass with CGO disabled; repository lint and config v2 artifact checks passed |
| C and documentation | LLVM 22 formatting/linting and repository Markdown lint passed |

Live arm64 execution and comparative overhead measurements remain unvalidated.
