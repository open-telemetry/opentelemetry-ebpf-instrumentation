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

## Protocol Parsing

### Multiple Commands per Packet

The parser supports multiple Couchbase commands in a single TCP packet.
The parser iteratively processes each command until all bytes are consumed

### Truncation Tolerance

The parser handles truncated packets gracefully:

- Header fields are always available (24 bytes minimum)
- Key and value are parsed up to available bytes
- Partial keys/values are returned without error
