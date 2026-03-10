# HTTP/2 & gRPC Context Propagation

This document describes the architecture and implementation of HTTP/2 and gRPC
distributed trace context propagation, extending the existing HTTP/1.1 mechanisms
documented in [context-propagation.md](context-propagation.md).

## Table of Contents

- [Current State](#current-state)
- [Architecture](#architecture)
- [Inbound Context Propagation](#inbound-context-propagation)
- [Outbound Context Propagation](#outbound-context-propagation)
  - [HPACK Encoding](#hpack-encoding)
  - [Sock_msg Injection Flow](#sock_msg-injection-flow)
  - [Constraints](#constraints)
- [Implementation Details](#implementation-details)
- [Testing](#testing)

## Current State

| Direction | HTTP/1.1 | HTTP/2 / gRPC |
|-----------|----------|---------------|
| **Inbound** (extract traceparent) | BPF: TC sock_ops (TCP options) + kprobe `protocol_http` (plaintext scan) → `incoming_trace_map` | **Go-side**: `readMetaFrame()` HPACK extraction + `applyTraceparent()` overrides BPF trace context. **BPF sock_msg** on the sender side populates `incoming_trace_map` for the receiver's `find_trace_for_server_request()`. |
| **Outbound** (inject traceparent) | BPF: sock_msg `bpf_msg_push_data()` injects 70-byte `Traceparent:` header | **BPF sock_msg**: `bpf_msg_push_data()` injects 69-byte HPACK-encoded `traceparent` header into HEADERS frames. |

## Architecture

### Why HTTP/1.1 mechanisms don't work for HTTP/2

HTTP/1.1 headers are plaintext: `Traceparent: 00-<trace_id>-<span_id>-<flags>\r\n`.
BPF programs can scan for and inject plaintext directly.

HTTP/2 headers are HPACK-compressed (RFC 7541). A header like `traceparent` might be:

- Huffman-encoded (variable-length bit codes)
- Referenced by dynamic table index
- Split across HEADERS + CONTINUATION frames

BPF programs cannot maintain HPACK dynamic table state or perform Huffman decoding.
This rules out BPF-side parsing of inbound HTTP/2 headers.

### What already works

1. **BPF trace context generation** (`protocol_http2.h` `http2_grpc_start()`):
   Generates trace_id, span_id, populates `tp_info_t` on `http2_grpc_request_t`,
   calls `server_or_client_trace()` which populates `outgoing_trace_map` and
   `traces_ctx_v1` (shared context map).

2. **Go-side inbound HPACK extraction** (`http2grpc_transform.go`):
   `readMetaFrame()` decodes HPACK headers using `golang.org/x/net/http2/hpack`,
   extracts `traceparent`, and `applyTraceparent()` overrides the BPF-generated
   trace context on the event.

## Inbound Context Propagation

The Go userspace handler in `http2grpc_transform.go` extracts traceparent from
HPACK-decoded headers and overrides the BPF-generated trace IDs. This is the
correct approach because:

- HPACK decompression requires stateful context (dynamic table) impossible in BPF
- Go has access to `golang.org/x/net/http2/hpack` for correct decoding
- The override happens before the span is emitted, so consumers see the correct IDs

The BPF side still generates a trace context (which populates `traces_ctx_v1` for
log enrichment), but the Go side corrects it when a traceparent header is present.

On the sender side, the BPF sock_msg program writes the trace context to
`incoming_trace_map` (keyed by sorted connection info), so that the receiver's
`find_trace_for_server_request()` can find the parent context.

## Outbound Context Propagation

When a service makes an outbound gRPC/HTTP2 call, the BPF sock_msg program
injects a 69-byte HPACK-encoded `traceparent` header into the HEADERS frame.
The trace context comes from `outgoing_trace_map`, which is populated by
`server_or_client_trace()` during HTTP/2 stream detection.

### HPACK Encoding

HPACK supports "Literal Header Field without Indexing" (RFC 7541 §6.2.2):

```
0x00              — literal, no indexing, new name (1 byte)
0x0b              — name length = 11, no Huffman (1 byte)
"traceparent"     — header name (11 bytes)
0x37              — value length = 55, no Huffman (1 byte)
"00-<32hex>-..."  — W3C traceparent value (55 bytes)
─────────────────────────────────────────
Total: 69 bytes (k_h2_tp_hpack_size)
```

Key properties:

- **No dynamic table impact**: "without indexing" (0x00 prefix) doesn't modify
  encoder or decoder table state. Safe to inject without coordination.
- **No Huffman**: Plain ASCII encoding. Trivial for BPF to write byte-by-byte.
- **Fixed size**: Always exactly 69 bytes. No variable-length encoding needed
  (name length 11 < 127, value length 55 < 127).

### Sock_msg Injection Flow

```
Original buffer:  [9-byte frame hdr][N-byte HPACK payload][next frame...]
                   ^                 ^                      ^
                   |                 |                      |
                   frame_offset      payload_start          next_frame

After injection:  [9-byte frame hdr][N-byte HPACK][69-byte tp HPACK][next frame...]
                   ^                                                  ^
                   |--- length field updated to N+69 ---|             |
```

Steps:

1. Detect HTTP/2 connection via `ongoing_http2_connections` map
2. Find HEADERS frame (type=0x01) with END_HEADERS flag (0x04) in buffer
3. Calculate injection point: `frame_offset + 9 + payload_length`
4. `bpf_msg_push_data(msg, injection_point, 69, 0)` — insert space
5. `bpf_msg_pull_data(msg, 0, msg->size, 0)` — make writable
6. Write 69-byte HPACK-encoded traceparent at injection point
7. Update 3-byte big-endian length at `frame_offset`: `old_length + 69`

### Constraints

| Constraint | Impact | Mitigation |
|------------|--------|------------|
| **TLS** | sock_msg sees ciphertext for userspace TLS (Go, OpenSSL) | Skip injection for SSL (same as HTTP/1.1). TCP options still work. |
| **Detection timing** | `ongoing_http2_connections` populated by kprobe (after sock_msg) | First send is preface → kprobe populates map. HEADERS come in subsequent sends. For same-buffer preface+HEADERS, detect preface directly. |
| **`outgoing_trace_map` timing** | Without uprobes, map not populated before sock_msg | Same limitation as HTTP/1.1 Scenario B. With Go/SSL uprobes, map is populated before sock_msg. |
| **CONTINUATION frames** | HEADERS may span multiple frames | Only inject when END_HEADERS (0x04) is set. |
| **BPF verifier** | Added instructions | Use tail calls (existing pattern). |
| **Existing traceparent** | App may already send traceparent | Duplicate header is valid per HTTP/2 spec. Go decoder uses last value. |

## Implementation Details

### Outbound injection flow (BPF)

The injection is implemented in `tpinjector.c` as part of the `obi_packet_extender`
sock_msg program:

1. **`find_h2_headers_frame(msg, &frame_offset, &payload_len)`**: Scans the
   sk_msg buffer for HTTP/2 preface (`PRI * HTTP/2.0`) and skips past it.
   Locates the first HEADERS frame (type=0x01) with END_HEADERS flag (0x04),
   scanning up to 4 frames (skipping SETTINGS, WINDOW_UPDATE, etc.).

2. **`obi_packet_extender_write_h2_tp`** (tail call): Calls
   `bpf_msg_push_data()` to insert 69 bytes at end of HPACK payload,
   `bpf_msg_pull_data()` to make writable, writes the HPACK-encoded
   traceparent byte-by-byte, and updates the 3-byte frame length field.

3. **Integration**: In `handle_existing_tp_pid()`, after the HTTP/1.1
   check fails, the code attempts HTTP/2 HEADERS injection. The main
   path (no tp_pid yet) also attempts HTTP/2 after `protocol_detector()`.

### Inbound extraction flow (Go)

The Go userspace handler in `http2grpc_transform.go`:

1. `readMetaFrame()` decodes HPACK headers using `golang.org/x/net/http2/hpack`
2. If `traceparent` is found, `applyTraceparent()` overrides BPF-generated
   trace/span IDs on the event

## Known Limitations

- **TLS**: sock_msg sees ciphertext for userspace TLS. Injection is skipped
  for SSL connections (same as HTTP/1.1). TCP options still work for TLS.
