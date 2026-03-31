# OBI Memcached text protocol parser

This document describes the Memcached text protocol parser that OBI provides.

## Protocol Overview

Memcached uses a line-oriented ASCII protocol on port `11211`.
All frames are terminated with `\r\n`.

Requests start with a lowercase command token; responses start with an uppercase status token
or a bare numeric value (for `incr`/`decr` replies).

### Command Set

OBI recognises this subset of the text protocol:

#### Retrieval

```
get <key>[ <key>...]\r\n
gets <key>[ <key>...]\r\n
gat <exptime> <key>[ <key>...]\r\n
gats <exptime> <key>[ <key>...]\r\n
```

#### Storage

```
set     <key> <flags> <exptime> <bytes> [noreply]\r\n<data>\r\n
add     <key> <flags> <exptime> <bytes> [noreply]\r\n<data>\r\n
replace <key> <flags> <exptime> <bytes> [noreply]\r\n<data>\r\n
append  <key> <flags> <exptime> <bytes> [noreply]\r\n<data>\r\n
prepend <key> <flags> <exptime> <bytes> [noreply]\r\n<data>\r\n
cas     <key> <flags> <exptime> <bytes> <cas-unique> [noreply]\r\n<data>\r\n
```

#### Delete, Arithmetic, Touch

```
delete   <key> [noreply]\r\n
incr     <key> <value> [noreply]\r\n
decr     <key> <value> [noreply]\r\n
touch    <key> <exptime> [noreply]\r\n
flush_all [exptime] [noreply]\r\n
```

#### Admin

```
stats [args]\r\n
version\r\n
```

`quit` and the newer meta commands are intentionally not detected. `quit` closes the connection
without a response and is too generic to classify safely with OBI's heuristic parser.

### Response Tokens

```
Storage:    STORED, NOT_STORED, EXISTS
Retrieval:  VALUE <key> <flags> <bytes>\r\n<data>\r\nEND
Delete:     DELETED, NOT_FOUND
Touch:      TOUCHED, NOT_FOUND
Arithmetic: <new-value>\r\n
Admin:      OK, VERSION <x.x.x>, STAT <name> <value>
Error:      ERROR, CLIENT_ERROR <reason>, SERVER_ERROR <reason>
```

## Detection Heuristic

Memcached detection happens in
[tcp_detect_transform.go](../../../pkg/ebpf/common/tcp_detect_transform.go)
after SQL, FastCGI, MongoDB, and Couchbase binary detection.

OBI classifies a TCP exchange as Memcached only when both captured buffers look like valid
Memcached frames:

- Request-side buffer starts with a known text command.
- Response-side buffer starts with a known text response token or a bare numeric counter value.
- Each frame's first line must be `\r\n` terminated.

### Request-Only Path (noreply on socket close)

A separate path runs before the main Memcached check (and before Redis) to handle request-only
events emitted on socket close. This path is intentionally narrow — kept separate so one-sided
ASCII payloads do not broadly claim unrelated TCP traffic:

- The response buffer must be empty.
- Every command in the request buffer must carry an explicit ASCII `noreply` modifier.
- Only commands that support `noreply` are accepted:
  `set`, `add`, `replace`, `append`, `prepend`, `cas`, `delete`, `incr`, `decr`, `touch`,
  `flush_all`.

## Protocol Parsing

Parsing logic lives in
[memcached_detect_transform.go](../../../pkg/ebpf/common/memcached_detect_transform.go).
The entry point for a confirmed exchange is `ProcessPossibleMemcachedEvent`.

It extracts:

- `db.operation.name` from the first request token, normalized to uppercase.
- Span `Path` from the first key when the command is key-oriented.
- Error status from `ERROR`, `CLIENT_ERROR`, and `SERVER_ERROR` responses.

### Command Normalization

All command tokens are uppercased for the span `Method` (`memcachedNormalizeCommand`).
`gets` is normalized to `GET`, and `gats` is normalized to `GAT`; in each pair the difference is
only in the response metadata, which OBI does not record.

### Coalesced Requests (Multiple Commands per Buffer)

The parser (`parseMemcachedRequests`) iterates the full request buffer to consume all pipelined
commands. A typical coalesced buffer contains one or more `noreply` commands followed by a single
reply-backed command:

```text
set session-key 0 300 5 noreply\r\nvalue\r\nget session-key\r\n
```

`memcachedReplyBackedOps` splits the list: all leading `noreply` commands become zero-duration
spans (emitted via `emitMemcachedNoreplySpans`), and the final reply-backed command is matched
against the response buffer for its status.

Storage commands (`set`, `add`, `replace`, `append`, `prepend`, `cas`) include a data block after
the header line. `memcachedStoragePayloadSize` validates the `<bytes>\r\n` block and accounts for
it before the next operation can be parsed.

### Reversed-Buffer Handling

If the request buffer parses as a response and the response buffer parses as a request, OBI swaps
roles (`reverseTCPEvent`) and re-processes. This handles exchanges where capture begins
mid-stream.

### Wire Exchange Examples

```text
get session-key\r\n
VALUE session-key 0 5\r\nvalue\r\nEND\r\n
```

```text
set session-key 0 300 5\r\nvalue\r\n
STORED\r\n
```

```text
incr counter 1\r\n
42\r\n
```

```text
set a 0 0 1 noreply\r\nx\r\nget a\r\n
VALUE a 0 1\r\nx\r\nEND\r\n
```

## Span Attributes

OBI emits Memcached spans with these OpenTelemetry attributes:

| Attribute | Source | Example |
|-----------|--------|---------|
| `db.system.name` | Constant | `"memcached"` |
| `db.operation.name` | Request command (uppercased) | `"GET"`, `"SET"` |
| `db.query.text` | First key (optional, when `db.query.text` is selected) | `"session-key"` |
| `db.response.status_code` | Error token (only on failure) | `"SERVER_ERROR"` |
| `server.address` | Connection info | Server hostname |
| `server.port` | Connection info | `11211` |

The span name is the normalized operation name alone (for example `GET`, `GAT`, `SET`),
keeping database span names low-cardinality and consistent with the existing Redis instrumentation.
`db.query.text` is emitted only when the attribute is opted in via the `attributes.select` config,
mirroring the Redis behaviour.

`db.response.status_code` is set only when the response starts with `ERROR`, `CLIENT_ERROR`, or
`SERVER_ERROR`; successful responses leave the attribute unset.

## Limitations

- **First key only**: For multi-key `GET`/`GETS`/`GAT`/`GATS` requests, only the first key
  is recorded in `db.query.text`; additional keys are not captured.
- **Noreply span timing**: Spans emitted for `noreply` commands have zero duration (`End = Start`);
  there is no response to bound the timing.
- **Payload not captured**: Value bytes are sized for frame boundary detection but are not
  included in span attributes.
- **Request-only path is strict**: Non-`noreply` request-only traffic (e.g. a `get` with no
  response) is not attributed as Memcached and is dropped.
- **Unsupported text commands**: `quit` and the newer meta commands are ignored.
