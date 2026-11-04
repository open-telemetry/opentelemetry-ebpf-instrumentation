# Exceptions

OBI exports captured exceptions as OpenTelemetry LogRecords. Language collectors
publish `exceptions.Event` values to `EBPFEventContext.ExceptionInput`. The shared
pipeline resolves the service, associates the exception with its request and
exports it through the logger provider.

## Configuration

```yaml
file_format: "1.0"
logger_provider:
  processors:
    - batch:
        exporter:
          otlp_http:
            endpoint: http://localhost:4318/v1/logs
extensions:
  obi:
    version: "2.0"
    capture:
      exceptions:
        enabled: true
```

## Log records

Each record has the `exception` event name and the `exception.type`,
`exception.message` and `exception.stacktrace` attributes. An event needs a type or
a message. An exception raised inside a request has severity ERROR (17), and one
that ends the process has FATAL (21), with the matching severity text. The record
timestamp is the capture time; the observed timestamp is when OBI read the event.
Every observation becomes its own record, exported as soon as it arrives,
independent of request completion, trace sampling, route filters and HTTP status
filtering.

`exception.stacktrace` uses the runtime's own text format, as the language's
OpenTelemetry SDK writes it, so parsers built for that format read it unchanged.

- The stacktrace starts with the runtime's header line, for example `Type: message`.
- Causes and inner exceptions keep the runtime's notation, down to the root cause.
  When space runs out, frames are dropped before causes.
- A shortened stacktrace ends frames on line boundaries and UTF-8 characters on
  character boundaries. Dropped frames become one line, `... N frames omitted`, or
  `... frames omitted` when the count is unknown, indented like the frames around
  it. A shortened message ends in `...`.

## Request association

An exception carries the trace context of the server request that owned it when
it was thrown. BPF producers write that context to the record header (`tp`),
with an `owner` value that says how the request was found
(`bpf/common/exception_event.h`):

| `owner` | Request |
|---|---|
| `ongoing` | The request the process was still serving. |
| `after_response` | The latest request on the connection that started before `capture_ns`, after its response was sent. |
| `thread` | The server request of the throwing thread. |
| `ambiguous` | None: a multiplexed connection without a stream id. |
| `none` | None. |

For `ongoing`, `after_response` and `thread`, the reader copies the trace id, span
id and trace flags to the event, and the LogRecord carries them. The span id is the
span that covered the request's processing: the server span, or its `processing`
child when the request was queued before processing started. Client calls made by
the request are parented to the same span. The other owners export the exception
without trace and span ids.

A process that exports its own traces has its OBI spans discarded
(`tracesgen.SpanDiscarded`), so its exceptions are exported without trace and span
ids.

## Producers

Collectors check the discovered service's `Exceptions.Enabled` before acquiring
payloads or installing exception-specific probes. Discovery combines global
settings, the effective rule override, logs export selection and sink
availability. `ExceptionInput` is set when exception capture is enabled. Each
`exceptions.Event` carries its resolved service, capture timestamp, exception
type, message and stacktrace, and the request's trace context when known.

BPF producers write to the `exception_events` ring (`bpf/maps/exception_events.h`).
A record is an `exception_event_header_t` (`bpf/common/exception_event.h`)
followed by `payload_len` bytes whose layout the runtime defines.

- `exception_record_start` and `exception_record_submit`
  (`bpf/common/exception_emit.h`) provide per-CPU scratch space and variable-size
  output. Producers check `g_exceptions_enabled` first.
- `capture_ns` holds `bpf_ktime_get_ns()` at throw time, and `pid` holds
  `task_pid()`: the reader resolves the service from both.
- Payloads up to `k_exception_payload_max_len` bytes are submitted.

In user space, a runtime adds its payload decoder to `exceptionPayloadDecoders`
(`pkg/ebpf/common/exception_record.go`). The shared reader resolves the service,
applies the header's trace context and forwards the event to `ExceptionInput`.
