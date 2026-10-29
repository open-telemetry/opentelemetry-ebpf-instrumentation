# Optional Frida Core binding

This internal package provides the small Frida Core API subset needed for the
planned OpenSSL propagation backend. It manages a local device, injected scripts,
messages, RPC, cancellation, and teardown through `purego` with `CGO_ENABLED=0`.
It does not enable process discovery or OpenSSL instrumentation. Those belong to
the subsequent integration described in [#3892](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3892).

The native implementation requires `-tags=obi_frida`, Linux, and amd64 or arm64.
Other builds return an unavailable-backend error from `Open`.
The OBI executable does not call this package yet; its behavior and static build
remain unchanged.

## Supply the native library

Users supply **Frida Core 17.24.3**. OBI does not download libraries at startup or
distribute Frida binaries in its release images. Native version changes require
updating the binding, checksums, compatibility documentation, and lifecycle tests
together. Operators are responsible for provisioning and updating their library.

The official [Core devkit](https://github.com/frida/frida/releases/tag/17.24.3)
contains a static archive rather than the shared library required by `purego`.
The helper verifies the pinned devkit SHA-256 before extracting it and links its
archive into `libfrida-core.so`. It also writes `SHA256SUMS` and a build manifest
with the compiler, source digest, ELF dependencies, and symbol versions.

On a glibc Linux host with a C compiler, curl, binutils, tar, and xz:

```sh
pkg/internal/frida/core/build-frida-core.sh "$PWD/bin/frida" amd64
```

Use `arm64` for an arm64 host. `CC` can select a target compiler for cross-linking;
compiling a library does not validate native callbacks or injection on that target.
The helper retains the public Frida and namespaced GLib symbols used by the binding.
Retain the applicable Frida and bundled dependency license notices when packaging
the library for your environment.

For a fixed amd64 build toolchain:

```sh
docker build -f pkg/internal/frida/core/Dockerfile.native \
  -t obi-frida-native-builder:17.24.3 .
mkdir -p bin/frida
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" \
  obi-frida-native-builder:17.24.3 \
  pkg/internal/frida/core/build-frida-core.sh /src/bin/frida amd64
```

The Dockerfile pins Ubuntu by digest and installs its toolchain from a fixed
package snapshot. Matching inputs and toolchains are needed for reproducible
output. Building this dependency needs a C toolchain; building Go callers does
not use CGO.

## Compatibility and troubleshooting

| Boundary | Current evidence or requirement |
| --- | --- |
| Native version | Exactly Frida Core 17.24.3; the binding checks the version before initialization |
| Linux amd64 | Live lifecycle tests passed with the prototype's Ubuntu 24.04 library |
| Linux arm64 | Compiled in the prototype; live validation runs on the dedicated CI runner |
| libc | The inspected amd64 library requires glibc symbols through 2.38 |
| Native dependencies | The inspected amd64 build needs glibc, libm, libgcc_s, and the ELF loader |
| Unsupported packaging | Musl/Alpine, older glibc hosts, and standard OBI images are unvalidated |

Inspect `readelf -d` and `readelf --version-info` for each architecture and build;
do not assume the amd64 dependency floor applies to another library. The tagged
binding uses the system dynamic loader even with CGO disabled. Python, Node.js,
a compiler, and development headers are unnecessary at runtime.

- **Library fails to load:** use an absolute path and check its architecture,
  required GLIBC symbol versions, and runtime dependencies against the host.
- **Missing symbol or wrong Frida version:** use the pinned Core devkit and helper;
  a Frida Server binary or a library that hides the namespaced GLib exports cannot
  satisfy this binding. Failures before initialization release the library handle.
- **Attachment denied:** check permissions to trace the target, Yama/ptrace policy,
  container seccomp, and other instrumentation already using the target entry points.
- **Backend unavailable:** build the caller with `-tags=obi_frida` on Linux amd64 or
  arm64. Installing the library alone does not select the native implementation.

## Lifecycle contract

Only one engine lifetime is supported per process. The owner must stop sessions
before closing the engine and serialize teardown against other operations.
Native callbacks copy borrowed strings and route integer user-data IDs through a
Go registry; C never retains a Go object pointer. Callbacks enqueue messages without
blocking on RPC or native teardown. Queue overflow signals `Failed` separately from
the target's `Detached` notification.

A GLib default loop runs on a locked Go OS thread. Native synchronous calls use
`GCancellable` connected to Go cancellation, and cancellation finishes before
unreferencing that object. Session teardown disconnects signals and releases
scripts and sessions. `Close(true)` eternalizes a script before detaching; the
caller must first arrange its target-side shutdown/drain behavior.

Engine teardown joins the signal loop and shuts down/deinitializes Frida. The
library stays mapped until process exit: `dlclose` after initialization caused an
exit crash in the prototype, consistent with native TLS destructors outliving
shutdown. Reinitialization and library unloading after initialization are not
supported.

## Run the tests

```sh
CGO_ENABLED=0 go test ./pkg/internal/frida/core
CGO_ENABLED=0 OBI_FRIDA_LIBRARY="$PWD/bin/frida/libfrida-core.so" \
  go test -tags=obi_frida -v -count=1 -timeout=2m ./pkg/internal/frida/core
```

The live test attaches to its own controlled `sleep` child, checks immediate and
delayed callbacks with forced Go garbage collection, exercises RPC and error
paths, repeats attachment/detachment, and verifies cancellation and target-exit
cleanup. It skips when `OBI_FRIDA_LIBRARY` is unset; the dedicated CI job supplies
the library and executes it on amd64 and arm64. Run the test once per process
because the engine cannot be reinitialized.
