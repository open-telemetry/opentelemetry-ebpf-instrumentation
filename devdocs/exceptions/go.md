# Go errors and panics

OBI captures panics and formatted errors from instrumented Go services:

- **Panics**: every call to `runtime.gopanic`. That covers `panic(v)`, runtime
  panics such as a nil pointer dereference, and panics that the application later
  recovers. Panics are captured by default when exception capture is enabled.
- **Formatted errors**: every error built by `fmt.Errorf`, including errors that
  the application later handles. Formatted errors are captured only with
  `go.formatted_errors: true`.

Each capture becomes one log record, as described in [README.md](README.md). Go
records have the type `go.panic` or `go.error` and the severity ERROR. A panic that
ends the process is also reported as ERROR, because when the panic starts OBI can't
tell whether it will be recovered.

## Configuration

```yaml
extensions:
  obi:
    version: "2.0"
    capture:
      exceptions:
        enabled: true
        go:
          panics: true             # default
          formatted_errors: false  # default
      rules:
        - action: include
          match:
            process:
              open_ports: "8080"
          refine:
            exceptions:
              go:
                formatted_errors: true
```

A rule's `refine.exceptions.go` overrides the global settings for the processes it
selects. Omitted fields inherit the global settings.

## Probes

| Function | Probe | Captures |
|---|---|---|
| `runtime.gopanic` | entry | panics |
| `fmt.errorf` (Go 1.26+) | return | formatted errors |
| `fmt.Errorf` (before Go 1.26) | return | formatted errors |

Go 1.26 split `fmt.Errorf` into an inlinable wrapper around `fmt.errorf`. When an
executable has `fmt.errorf`, OBI probes only that function, so each error is
recorded once.

The probes are attached per process, and only to processes that capture the
matching kind. Exceptions raised before OBI attaches to a process are not
captured.

## What is captured

| Go code | Record | `exception.message` |
|---|---|---|
| `fmt.Errorf("lookup %s: %w", id, err)` | `go.error` | `lookup 42: …` |
| `fmt.Errorf` in a child goroutine | `go.error` | the formatted message, without request association |
| `errors.New("boom")`, sentinel errors | none | |
| `fmt.Sprintf`-based errors, such as gRPC `status.Errorf` | none | |
| `panic("boom")`, `panic(fmt.Sprintf(...))` | `go.panic` | `boom` |
| A named string type without methods | `go.panic` | the string |
| A nil pointer dereference | `go.panic` | `runtime error: invalid memory address or nil pointer dereference` |
| Integer division by zero | `go.panic` | `runtime error: integer divide by zero` |
| Closing a nil channel | `go.panic` | `close of nil channel` |
| Accessing a truncated memory-mapped file with `debug.SetPanicOnFault(true)` | `go.panic` | `runtime error: invalid memory address or nil pointer dereference` |
| An index out of range | `go.panic` | `runtime error: index out of range [5] with length 3` |
| Invalid slice bounds | `go.panic` | Go's slice-bounds message, including the failed bounds |
| A slice-to-array conversion with too few elements | `go.panic` | Go's conversion message, using the application's Go version |
| `panic(errors.New("boom"))` | `go.panic` | `boom` |
| `panic(fmt.Errorf("failed: %w", err))` | `go.panic` | the stored formatted message |
| `panic(5)`, `panic(true)` | `go.panic` | `5`, `true` |
| Other error types, Stringers, named numeric types, floats, `panic(nil)` | `go.panic` | empty |

A wrap chain records each `fmt.Errorf` call in it. For example,
`fmt.Errorf("a: %w", fmt.Errorf("b"))` produces two records.

OBI identifies panic types from the executable's Go metadata. Plain strings use
their captured bytes. For `runtime.errorString` and `runtime.errorAddressString`,
OBI adds the `runtime error:` prefix and a space, as Go's `Error` method does.
`runtime.plainError` uses its stored text directly, as in `close of nil channel`.
Bounds errors are formatted from the captured bounds and error code. Standard
errors from `errors.New` and `fmt.Errorf` store their formatted message in a
leading string field. Predeclared signed and unsigned integers, including
`uintptr`, and booleans use their captured value.

When BPF cannot read constant message bytes
from a process, OBI reads them from a read-only segment of the executable.
This fallback requires a captured string address and length. If the string
header is unreadable, or the text is in unreadable heap memory, the message is
empty. Type identification also works in binaries stripped with `-ldflags="-s -w"`.

Other string types with methods produce an empty message. Their `Error` or
`String` methods can render text differently from the stored bytes. When type
lookup fails, OBI keeps captured text only if BPF identified a predeclared string.

Captured string text contains up to 127 bytes and ends at the first NUL byte.
Runtime-error prefixes and bounds messages are rendered in user space.

## Stack traces

The BPF probe walks the goroutine's frame pointers and sends up to 32 return
addresses. User space symbolizes them with the Go PC table (`.gopclntab`), read
by the OpenTelemetry eBPF profiler's `elfunwindinfo.Gopclntab`. That table remains
in stripped executables, so stripped and unstripped builds produce the same
stacks. The load bias of each process is subtracted first, so PIE executables are
symbolized like the others.

`exception.stacktrace` follows the layout of `runtime.Stack`:

```text
panic: boom

main.handler(...)
	/app/main.go:42
net/http.HandlerFunc.ServeHTTP(...)
	/usr/local/go/src/net/http/server.go:2338
```

- Panics start with the `panic: <message>` header and a blank line. Errors start
  with the first frame.
- Frames are listed innermost first. Leading `fmt.Errorf`, `fmt.errorf`,
  `errors.New` and `runtime.gopanic` frames are dropped, so the stack starts at
  the code that raised the exception.
- Unexported `runtime` functions are hidden, as `runtime.Stack` hides them.
- A stack that filled all 32 slots without reaching `runtime.goexit` ends with
  `... frames omitted`.

The symbol table is loaded at the first exception of an executable and shared by
its processes. OBI keeps a descriptor to the executable, so stacks stay readable
after the process exits or the file is replaced.

### Known limits

- **Inlined calls are not expanded.** An inlined function's frame is missing, and
  its caller shows the inlined function's file and line. On Go 1.26+, where
  `fmt.Errorf` is inlined, the top frame of a formatted error shows
  `fmt/errors.go`. Expansion needs inline support in the profiler's symbolizer
  (`open-telemetry/opentelemetry-ebpf-profiler#1580`).
- **A frameless leaf function loses its caller.** A leaf function without a frame
  pointer that faults, such as a small method with a nil receiver, is followed by
  its caller's caller.

## Request association

An exception raised on the goroutine that serves a `net/http` request carries that
request's trace context, with owner `ongoing`. HTTP/1 requests go through
`ServeHTTP`, and HTTP/2 requests go through `http2serverConn.runHandler`. Only
HTTP/1 is covered by the integration test.

- Exceptions on other goroutines, including goroutines that the handler starts,
  have no request association.
- gRPC server requests have no request association.
- When `net/http` recovers a handler panic, the request's span ends when the
  connection's `serve` returns. No response was written, so the span's
  `http.response.status_code` is 0.

## Tests

`TestGoExceptions` (`internal/test/integration/go_exceptions_test.go`) builds the
fixture in `internal/test/integration/components/go-exceptions` with each Go
version and build mode of the [support matrix](README.md#support-matrix). It also
covers the per-rule `panics` and `formatted_errors` settings and a service with
exception capture disabled.
