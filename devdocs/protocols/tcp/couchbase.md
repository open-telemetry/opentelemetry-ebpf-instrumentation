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

## SQL++ (N1QL) Query Parsing

In addition to the binary KV protocol on port 11210, Couchbase supports SQL++ (also known as N1QL) queries via HTTP on port 8093. OBI can parse these HTTP-based queries to generate database spans.

**Note:** SQL++ parsing is a generic feature that works with any database using the SQL++ protocol, not just Couchbase. When the response contains the N1QL version header, `db.system.name` is set to `"couchbase"`. Otherwise, it is set to `"other_sql"` for non-Couchbase SQL++ endpoints.

### How It Works

SQL++ queries are sent as HTTP POST requests to the `/query/service` endpoint. OBI intercepts these HTTP requests and:

1. **Detects SQL++ requests** by matching the endpoint pattern (`/query/service`)
2. **Parses the request body** to extract the SQL statement and query context
3. **Identifies Couchbase** by checking for the `version=X.X.X-N1QL` parameter in the response's `Content-Type` header
4. **Extracts operation and table** using the standard SQL parser
5. **Parses namespace information** from the table path or `query_context` field

### Request Formats

SQL++ requests can be sent in two formats:

**JSON:**

```json
{
  "statement": "SELECT * FROM `bucket`.`scope`.`collection` WHERE id = $1",
  "query_context": "default:`bucket`.`scope`"
}
```

**Form-encoded:**

```
statement=SELECT+*+FROM+users&query_context=default:`mybucket`.`myscope`
```

### Namespace Resolution

The parser extracts bucket and collection information from multiple sources:

1. **Table path in statement**: `SELECT * FROM`bucket`.`scope`.`collection``
   - Bucket: `bucket`
   - Collection: `scope.collection`

2. **query_context field**: When present, provides the default namespace
   - Format: `default:`bucket`.`scope``
   - The bucket is extracted from this context if not in the table path

3. **Single identifier**: Interpretation depends on whether `query_context` is set
   - With `query_context`: treated as collection name
   - Without `query_context`: treated as bucket name (legacy mode)

### Response Error Handling

SQL++ responses include a status field and optional errors array:

```json
{
  "status": "fatal",
  "errors": [
    {
      "code": 12003,
      "msg": "Keyspace not found in CB datastore: default:bucket.scope.collection"
    }
  ]
}
```

When `status` is not `"success"`, OBI captures the first error's code and message.

### Span Attributes

SQL++ spans are generated with the following attributes:

| Attribute                 | Source                     | Example                              |
|---------------------------|----------------------------|--------------------------------------|
| `db.system.name`          | N1QL header detection      | `"couchbase"` or `"other_sql"`       |
| `db.operation.name`       | SQL parser                 | `"SELECT"`, `"INSERT"`, `"UPDATE"`   |
| `db.namespace`            | Table path / query_context | `"mybucket"`                         |
| `db.collection.name`      | Table path                 | `"myscope.mycollection"`             |
| `db.query.text`           | Request body               | `"SELECT * FROM users WHERE id = ?"` |
| `db.response.status_code` | Error code (on error)      | `"12003"`                            |
| `error.type`              | Error message (on error)   | `"Keyspace not found..."`            |

### Configuration

SQL++ parsing requires the following configuration:

- `OTEL_EBPF_HTTP_SQLPP_ENABLED` - Enable/disable SQL++ parsing (default: `false`)
- `OTEL_EBPF_BPF_BUFFER_SIZE_HTTP` - Must be set to a larger value (e.g., `2048`) to capture SQL++ request/response bodies. The default HTTP buffer size is insufficient for parsing SQL++ queries.
- Endpoint patterns are configured internally to match `/query/service`

### Implementation

The SQL++ parsing logic is implemented in:

- [sqlpp.go](../../../pkg/ebpf/common/http/sqlpp.go) - Main parsing logic
- [sqlpp_test.go](../../../pkg/ebpf/common/http/sqlpp_test.go) - Unit tests
