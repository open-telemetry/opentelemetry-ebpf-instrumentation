# OBI PostgreSQL protocol parser

This document describes the PostgreSQL protocol parser that OBI provides.

## Protocol Overview

PostgreSQL uses the [frontend/backend protocol (version 3)](https://www.postgresql.org/docs/current/protocol-message-formats.html).
After the startup handshake, every message exchanged over the connection has the
same shape:

```
[ 1 byte: message type ] [ 4 bytes: length ] [ ...body... ]
       e.g. 'Q'             big-endian Int32      payload
```

Two details are important for the parser:

- The **length** field is encoded in network byte order (big-endian).
- The length field **counts itself** (its own 4 bytes) but **not** the leading
  type byte. So a message that declares a length of `13` occupies `1 + 13 = 14`
  bytes on the wire, and the smallest valid length is `4` (a message with an
  empty body, such as `Sync`).

A single TCP segment frequently carries **several concatenated messages**. For
example, an extended-protocol query is sent as `Parse` + `Bind` + `Describe` +
`Execute` + `Sync` in one segment.

The frontend (client) message types OBI uses to recognise a connection are:

- `'Q'` — Query (simple query)
- `'P'` — Parse, `'B'` — Bind, `'E'` — Execute (extended query)

## Protocol Detection

Detection happens in the kernel in `is_postgres`
([protocol_postgres.h](../../../bpf/generictracer/protocol_postgres.h)). It walks
up to `k_pg_messages_in_packet_max` (10) messages in the captured segment,
following each message's declared length, and classifies the connection as
PostgreSQL when **all** of the following hold:

1. At least one frontend command message (`Q`/`P`/`B`/`E`) is seen.
2. Every parsed message is structurally valid: its declared length is `>= 4`.
3. Only messages that **fit entirely** within the captured segment are counted.

A message whose declared length overruns the buffer is **not** counted — it is
either a message split across TCP segments (legitimate) or bogus data, and the
parser stops and decides based on the complete messages seen so far.

### Why `message_size == data_len` is not required

An earlier version of the parser only classified a connection when the sum of
the parsed message lengths exactly matched the segment size
(`message_size == data_len`). That rejected several common, valid cases and
caused PostgreSQL connections to go undetected (see
[issue #1464](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1464)):

- **Multiple concatenated messages** whose total does not exactly fill the
  segment.
- **More than 10 messages** in a single segment: the parser stops at the loop
  limit, so `message_size < data_len`.
- **A final message split across TCP segments**: the tail is incomplete, so the
  totals never match.

Requiring a well-formed frontend command instead of an exact size match fixes
these cases.

### Avoiding false positives

Relaxing the size check could let non-PostgreSQL traffic be misclassified, so
the "fits entirely within the segment" rule (point 3 above) doubles as the guard
against it. Text-based protocols are rejected naturally: their bytes are
printable ASCII, so when interpreted as a big-endian length they produce huge
values that cannot fit in the segment.

For example, an HTTP `POST` request begins with the bytes `P`, `O`, `S`, `T`.
The `'P'` looks like a `Parse` command, but the following four bytes `"OST "`
decode to a length of `0x4F535420` (~1.3 billion). That message cannot fit in
the segment, so it is not counted, no frontend command is recorded, and the
connection is correctly rejected. Only binary data with small, self-consistent,
chained lengths — i.e. genuine PostgreSQL — passes the filter.

## Protocol Parsing

Once a connection is classified as PostgreSQL, request and response bytes are
streamed to userspace and parsed there. The entry points are
`isPostgres` / `isValidPostgresPayload` and the query/statement handling in
[sql_detect_postgres.go](../../../pkg/ebpf/common/sql_detect_postgres.go), driven
from [sql_detect_transform.go](../../../pkg/ebpf/common/sql_detect_transform.go).
SQL statement normalisation and pruning live in the
[sqlprune package](../../../pkg/internal/sqlprune).

## Tests

The kernel-side classifier has a host-compilable unit test in
[bpf_postgres_detection.c](../../../bpf/tests/bpf_postgres_detection.c) that
covers the detection and false-positive cases above. End-to-end coverage with a
real PostgreSQL server lives in the `TestSuite_PythonPostgres` integration
suite.
