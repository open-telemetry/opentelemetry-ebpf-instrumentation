# OBI Couchbase protocol parser

This document describes the Couchbase protocol parser that OBI provides.

## Protocol Overview

Couchbase bases its client-server communication on
the [Memcached Binary Protocol](https://github.com/couchbase/memcached/blob/master/docs/BinaryProtocol.md),
[extending it](https://github.com/couchbase/kv_engine/tree/master/include/mcbp/protocol) with custom opcodes and features.
This is a binary protocol with a fixed 24-byte header followed by optional body data.

### Packet Header Format

All packets share the same 24-byte header structure:

```
Header (24 bytes):
  magic         => UINT8   (byte 0)
  opcode        => UINT8   (byte 1)
  key_length    => UINT16  (bytes 2-3, big-endian)
  extras_length => UINT8   (byte 4)
  data_type     => UINT8   (byte 5)
  vbucket/status=> UINT16  (bytes 6-7, big-endian)
  body_length   => UINT32  (bytes 8-11, big-endian)
  opaque        => UINT32  (bytes 12-15, big-endian)
  cas           => UINT64  (bytes 16-23, big-endian)
```

**Magic bytes** identify the packet direction:

- `0x80` | `0x08` - Client request (client → server)
- `0x81` | `0x18` - Server response (server → client)
- `0x82` - Server request (server → client, for server-initiated commands)
- `0x83` - Client response (client → server, response to server request)

**Bytes 6-7** serve dual purpose:

- In requests: VBucket ID (partition identifier)
- In responses: Status code

### Body Structure

The body follows the header and contains (in order):

1. **Extras** - Command-specific extra data (e.g., flags, expiration for SET)
2. **Key** - Document key (for key-based operations)
3. **Value** - Document value or additional data

Body length = `extras_length + key_length + value_length`

### Connection Setup Commands (Not Traced)

These commands are tracked for state but don't generate spans:
They are used to enrich subsequent operations with bucket and collection context.

| Opcode | Name              | Purpose                                    |
|:-------|:------------------|:-------------------------------------------|
| 0x89   | SELECT_BUCKET     | Selects the bucket for the connection      |
| 0xbb   | GET_COLLECTION_ID | Resolves scope.collection to collection ID |

## Bucket/Scope/Collection Tracking

Couchbase uses a hierarchical namespace: **Bucket → Scope → Collection**

### Connection-Scoped State

Unlike protocols where namespace is per-request, Couchbase uses connection-level state:

1. **SELECT_BUCKET (0x89)**: Client sends bucket name in key field. On success, all subsequent operations use this
   bucket.

2. **GET_COLLECTION_ID (0xbb)**: Client sends `scope.collection` in value field to resolve to a Collection ID (CID). On
   success, we cache the scope and collection names.

This is analogous to:

- MySQL's `USE database`
- Redis's `SELECT db_number`

### Per-Connection Cache

OBI maintains a per-connection cache (`couchbaseBucketCache`) that stores:

- `Bucket` - Selected bucket name
- `Scope` - Current scope name
- `Collection` - Current collection name

**Limitation**: If SELECT_BUCKET occurs before OBI starts tracing, the bucket name will be unknown for that connection.

## Protocol Parsing

The Couchbase packet parsing flow:

1. TCP packets arrive at `ReadTCPRequestIntoSpan`
   in [tcp_detect_transform.go](../../../pkg/ebpf/common/tcp_detect_transform.go)

2. `ProcessPossibleCouchbaseEvent`
   in [couchbase_detect_transform.go](../../../pkg/ebpf/common/couchbase_detect_transform.go) attempts to parse the
   packet

3. Parsing logic lives in the [couchbasekv package](../../../pkg/internal/ebpf/couchbasekv/):
    - `types.go` - Protocol constants (Magic, Opcode, Status, DataType)
    - `header.go` - Header and Packet parsing with truncation tolerance
    - `reader.go` - PacketReader utility for reading binary data

### Multiple Commands per Packet

The parser supports multiple Couchbase commands in a single TCP packet.
The parser iteratively processes each command until all bytes are consumed

### Truncation Tolerance

The parser handles truncated packets gracefully:

- Header fields are always available (24 bytes minimum)
- Key and value are parsed up to available bytes
- Partial keys/values are returned without error

## Span Attributes

OBI generates spans with the following OpenTelemetry semantic conventions:

| Attribute                 | Source            | Example              |
|---------------------------|-------------------|----------------------|
| `db.system.name`          | Constant          | `"couchbase"`        |
| `db.operation.name`       | Opcode            | `"GET"`, `"SET"`     |
| `db.namespace`            | Bucket + Scope    | `"mybucket.myscope"` |
| `db.collection.name`      | Collection        | `"mycollection"`     |
| `db.response.status_code` | Status (on error) | `"1"`                |
| `server.address`          | Connection info   | Server hostname      |
| `server.port`             | Connection info   | `11210`              |

## Configuration

Couchbase tracing can be configured via:

- `ebpf.CouchbaseDBCacheSize` - Size of per-connection bucket cache (default matches other protocols)
