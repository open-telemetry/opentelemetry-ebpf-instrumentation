# OBI Aerospike protocol parser

This document describes the Aerospike protocol parser that OBI provides.

## Protocol Overview

Aerospike clients talk to the server over a custom binary protocol (the native
"proto version 2" protocol) on the service port (default **3000**). It is a
length-prefixed binary protocol — not HTTP, gRPC, or Protocol Buffers despite
the unfortunate "proto" name. OBI parses this wire format in userspace: the
request and response payloads of an unclassified TCP connection are handed to
the Aerospike parser. The protocol is **one-request-one-response per connection
(FIFO)**, so the generic per-connection direction-flip correlation is exact.

### proto header (8 bytes, every message)

All multi-byte integers are big-endian.

```
proto header (8 bytes):
  version => UINT8   (byte 0)      always 2
  type    => UINT8   (byte 1)      message type (see below)
  size    => UINT48  (bytes 2-7)   body length (not incl. this header)
```

**Message types** (the `type` byte):

| type | Meaning            | Traced? |
|:-----|:-------------------|:--------|
| 1    | Info (ASCII admin) | No      |
| 2    | Security / auth    | No      |
| 3    | AS_MSG (data)      | **Yes** |
| 4    | Compressed AS_MSG  | No (v1) |

Only type-3 AS_MSG frames carry record operations and produce spans. Type-1
(info/admin text) and type-2 (login/auth) frames are ignored. Type-4 compressed
frames are skipped in this version (the zlib body is opaque to byte parsing;
compression is off by default in the clients and only kicks in above 128 bytes).

### AS_MSG header (22 bytes)

For type-3 messages the body begins with a fixed 22-byte header:

```
as_msg header (22 bytes):
  header_sz       => UINT8   (byte 0)      always 22
  info1           => UINT8   (byte 1)      read-side flags
  info2           => UINT8   (byte 2)      write-side flags
  info3           => UINT8   (byte 3)      misc flags
  info4           => UINT8   (byte 4)
  result_code     => UINT8   (byte 5)      0 = OK (in responses)
  generation      => UINT32  (bytes 6-9)
  record_ttl      => UINT32  (bytes 10-13)
  transaction_ttl => UINT32  (bytes 14-17)
  n_fields        => UINT16  (bytes 18-19)
  n_ops           => UINT16  (bytes 20-21)
```

Then `n_fields` variable-length fields, then `n_ops` variable-length operations:

```
field:  field_sz => UINT32 (len of type+value), type => UINT8, value => field_sz-1 bytes
op:     op_sz    => UINT32, op => UINT8, particle_type => UINT8, version => UINT8,
        name_sz  => UINT8, name => name_sz bytes, value => remaining bytes
```

### Operation classification

There is no single opcode byte; the operation is derived from the info flags
plus, for writes, the per-op type bytes:

| Operation | How it is detected                                                  |
|:----------|:-------------------------------------------------------------------|
| `BATCH`   | `info1 & 0x08` (BATCH)                                              |
| `UDF`     | a UDF field (type 30–33) is present                                 |
| `DELETE`  | `info2 & WRITE` and `info2 & DELETE`                                |
| `PUT`     | `info2 & WRITE`, all ops are WRITE (op type 2)                      |
| `TOUCH`   | `info2 & WRITE`, the only op is a TOUCH (op type 11)               |
| `OPERATE` | `info2 & WRITE`, mixed/other ops (increment, append, CDT, read…)   |
| `QUERY`   | `info1 & READ` and an index field (type 21–26) is present           |
| `SCAN`    | `info1 & READ`, no digest field (whole-set/partition read)          |
| `EXISTS`  | `info1 & READ` and `info1 & GET_NO_BINS` (0x20), with a digest      |
| `GET`     | `info1 & READ` with a digest field                                  |

### Fields extracted

| Field            | type | Used for                                              |
|:-----------------|:-----|:------------------------------------------------------|
| namespace        | 0    | `db.namespace`                                        |
| set              | 1    | `db.collection.name`                                  |
| key              | 2    | user key (only present when client `sendKey` is on)   |
| digest           | 4    | record fingerprint (high-cardinality; not emitted)    |
| index 21–26      |      | distinguishes QUERY                                    |
| UDF 30–33        |      | distinguishes UDF                                      |
| batch 41/42      |      | batch sub-requests (count → `db.operation.batch.size`)|

## Correlation, truncation, and streaming

- **Correlation** is the generic per-connection direction flip (request then
  response). Aerospike does not multiplex multiple in-flight requests on a
  connection, so this is exact for single-record operations.
- **Truncation tolerance**: the parser always advances by the declared field/op
  sizes and stops at the end of the captured buffer. scan/query requests can be
  several KB (they carry a partition/digest list), exceeding the inline capture
  buffer — but the namespace, set, and index fields sit at the front, so
  classification and namespace/collection extraction survive truncation.
- **Streaming responses**: scan/query/batch return many response frames
  terminated by the `INFO3_LAST` flag. OBI builds the span from the **request**
  frame's metadata (operation, namespace, set, batch size) and reads the status
  from the first response frame; it does not aggregate the full multi-frame
  stream.

## Protocol Parsing

1. TCP packets arrive at `ReadTCPRequestIntoSpan`
   in [tcp_detect_transform.go](../../../pkg/ebpf/common/tcp_detect_transform.go).
2. `matchAerospike` (in the heuristic detection stage) recognizes the proto
   header and parses the request.
3. Parsing logic lives in
   [aerospike_detect_transform.go](../../../pkg/ebpf/common/aerospike_detect_transform.go):
   `parseAerospikeRequest` (op classification + field extraction),
   `aerospikeStatus` (result code), and `TCPToAerospikeToSpan` (span building).

## Span Attributes

| Attribute                 | Source                | Example                  |
|---------------------------|-----------------------|--------------------------|
| `db.system.name`          | Constant              | `"aerospike"`            |
| `db.operation.name`       | info flags + op bytes | `"GET"`, `"PUT"`         |
| `db.namespace`            | namespace field       | `"test"`                 |
| `db.collection.name`      | set field             | `"users"`                |
| `db.operation.batch.size` | batch field (BATCH)   | `3`                      |
| `db.query.text`           | user key (opt-in)     | `"k_put"`                |
| `db.response.status_code` | result_code (on error)| `"KEY_EXISTS_ERROR"`     |
| `server.address`          | connection info       | Server hostname          |
| `server.port`             | connection info       | `3000`                   |

The span name follows the OTel database convention `{operation} {target}`, e.g.
`GET test.users` (`{db.operation.name} {db.namespace}.{db.collection.name}`).

### User key (opt-in)

Capturing `db.query.text` **requires the client to enable the send-key write
policy** (the "Send Key" section of the
[Aerospike policies docs](https://aerospike.com/docs/server/guide/policies) —
`AS_POLICY_KEY_SEND`, exposed as `sendKey` in the clients, e.g.
`WritePolicy.sendKey = true` in the Java client). By default Aerospike clients
send only the key's RIPEMD-160 digest on the wire, not the key itself, so without
send-key there is nothing for OBI to read and `db.query.text` is absent.

When `sendKey` is set, the request carries the user key (field type 2).
`db.query.text` carries **only that primary key** — the identifier the
application used to address the record (e.g. `k_put`) — not the bin names/values
or any record payload. This differs from a protocol like Couchbase KV where the
document body is on the wire; Aerospike record/bin values are not captured (see
Limitations).

OBI decodes the key only when its particle type is string (integer/blob keys are
binary and high-cardinality, so they are skipped), and emits it **only when the
`db.query.text` attribute is explicitly selected** (`attributes.select`). The
20-byte RIPEMD-160 digest is never emitted — it is high-cardinality and a
one-way hash of the key.

TLS-encrypted connections are also supported: OBI's TLS instrumentation captures
the decrypted payloads, so the AS_MSG frames are parsed the same as cleartext.

## Limitations

- **Compression**: type-4 compressed AS_MSG frames are skipped (off by default
  in the clients).
- **Multi-record data**: only operation metadata is captured, not returned
  record/bin values.
- **Response status codes are client/SDK-dependent**: `db.response.status_code`
  is parsed from the response `result_code`, which lives in the `as_msg` body. It
  is only populated when the captured response buffer includes that body. Whether
  it does depends on how the client SDK reads the response from the socket:
  - The **Java client** (`aerospike-client-jdk21`) reads each response in two
    steps — an 8-byte proto-header read, then a separate read for the body — so
    on the generic TCP path only the header is captured and the `result_code` is
    not observed (error status stays unset).
  - SDKs that read the whole response in a single recv leave the full first frame
    in the captured buffer, so the `result_code` is read and error status is
    emitted.

  Capturing the body regardless of the client's read pattern would require
  kernel-side response reassembly (an eBPF change outside this parser's scope).

## Configuration

Aerospike tracing is enabled by including `aerospike` in the traces/metrics
instrumentation selection (it is on by default for traces). For example:

```yaml
otel_traces_export:
  instrumentations:
    - aerospike
```

or via environment variables:

```
OTEL_EBPF_TRACES_INSTRUMENTATIONS=aerospike
OTEL_EBPF_METRICS_INSTRUMENTATIONS=aerospike
```

## Semantic conventions and prior art

Aerospike is **not** part of the OpenTelemetry semantic conventions: there is no
registered `db.system.name` value for it, so OBI emits `aerospike` as a custom
value, following the spec's guidance to use a custom value when no well-known one
applies. Otherwise this parser maps onto the standard, stable OTel database span
attributes (`db.operation.name`, `db.collection.name`, `db.namespace`,
`db.operation.batch.size`, `db.query.text`, `db.response.status_code`).

There is **no official OpenTelemetry instrumentation for Aerospike**, and no
client-side tracing for it anywhere in the ecosystem. The existing Aerospike
observability tooling is metrics-only:

- **Server-side metrics**: the OpenTelemetry Collector
  [`aerospikereceiver`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/aerospikereceiver)
  (`aerospike.node.*`, `aerospike.namespace.*`) and the official
  [aerospike-prometheus-exporter](https://github.com/aerospike/aerospike-prometheus-exporter)
  (`aerospike_node_*`, `aerospike_namespace_*`, …) both scrape the server.
- **Client-side metrics**: the official Aerospike client libraries
  ([Java](https://aerospike.com/docs/develop/client/java/metrics/),
  [Go](https://aerospike.com/docs/develop/client/go/metrics/)) expose built-in
  latency histograms per command type, but emit no spans and have no out-of-the-box
  OTel exporter.

So OBI's client-side span generation here is novel — it is the only source that
produces per-operation traces for Aerospike.

## References

- Aerospike wire protocol (info & AS_MSG):
  <https://aerospike.com/docs/server/architecture/wire-protocol>
- Aerospike client (`as_msg`) message format and info/result codes:
  <https://github.com/aerospike/aerospike-client-c> (the C client headers are the
  canonical reference for the field/op/particle type ids and result codes used here)
- OTel database semantic conventions (spans):
  <https://opentelemetry.io/docs/specs/semconv/database/database-spans/>
