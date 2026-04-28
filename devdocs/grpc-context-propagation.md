# gRPC/HTTP2 Context Propagation

Builds on the general [Context Propagation Architecture](context-propagation.md).

## Overview

Injects `traceparent` HPACK headers into outgoing HTTP/2 HEADERS frames and parses them on the receiving side. Two network mechanisms:

1. **sk_msg HPACK injection** — inserts traceparent into HEADERS frames via `bpf_msg_push_data`
2. **TCP options** — carries trace context in TCP option kind 25

All cross-process propagation is network-only.

## Egress

### sk_msg Injection Chain

```
obi_packet_extender
  └─ detect_h2           — find HEADERS frame, extract stream_id
       └─ find_existing   — check if traceparent already exists in HPACK
            └─ create_tp  — look up parent from outgoing_trace_map[{ports, stream_id}]
                 └─ write_tp — push 69 bytes of HPACK via bpf_msg_push_data
```

H2 detection: checks for `PRI *` preface or `sk_h2_conn_flag` socket storage (set on first detection, auto-freed on socket close). Scans up to 4 frames for HEADERS with `END_HEADERS`.

Parent lookup priority in `create_tp`:

1. `outgoing_trace_map[{ports, stream_id}]` — written by Go uprobe or kprobe CLIENT
2. `find_parent_trace` — general fallback chain: Node.js → Python → nginx → Puma → Java → process traces → `cp_support_connect_info`

### Go Uprobe Path

1. **`transport_http2Client_NewStream`** — caches `conn_ptr → connection_info_t` in `grpc_conn_ptr_to_conn`
2. **`grpcFramerWriteHeaders`** — has both stream_id and trace context. Writes `outgoing_trace_map[{ports, stream_id}]`. Also injects traceparent via `bpf_probe_write_user` when `g_bpf_header_propagation` is true.

### TCP Options

`schedule_write_tcp_option` stores trace in socket storage. sock_ops `write_hdr_cb` writes TCP option kind 25 on every outgoing segment.

## Ingress

- **TCP options**: sock_ops `parse_hdr_cb` reads option kind 25, stores in `incoming_trace_map`
- **HPACK parsing**: kprobe `http2_grpc_start` (SERVER) checks `incoming_trace_map` first, falls back to `parse_hpack_traceparent` on the captured frame data

## Parent Trace Linking

`outgoing_trace_map` is keyed by `egress_key_t = {s_port, d_port, stream_id}`. The `stream_id` isolates concurrent multiplexed streams on the same connection.

Writers:

- **Go uprobe** (`grpcFramerWriteHeaders`) — `BPF_ANY` with `written=1`, definitive trace from Go runtime
- **kprobe CLIENT** (`http2_grpc_start`) — `BPF_NOEXIST` with `written=0`, used only when no uprobe wrote first; span_id comes from `urand_bytes`

`adopt_injected_trace`: called after `find_trace_for_client_request` in the kprobe CLIENT path. Overrides stale traces with whatever is in `outgoing_trace_map[{ports, stream_id}]`.

## Known Limitations

### Persistent connections established before OBI

If a gRPC connection's HTTP/2 preface was sent before OBI attached, `ongoing_http2_connections` is never populated. The kprobe won't recognize subsequent frames as HTTP/2.

**Affected**: Non-Go services with persistent channels established at startup. Go services with uprobes are unaffected.

### Go lazy connect without uprobes

`grpc.NewClient` connects lazily on a background goroutine. Without Go uprobes (`OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=true`), `cp_support_connect_info` records the wrong thread and parent lookup fails.

**With uprobes**: Not affected.

### loopyWriter race on a fresh stream

When `loopyWriter` dequeues HEADERS before `NewStream_ret` has published `ongoing_streams`, the first frame on a new stream is sent without OBI's traceparent. Subsequent frames inject normally.

## Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `sk_h2_conn_flag` | SK_STORAGE | socket | `u8` | Marks socket as HTTP/2 |
| `ongoing_http2_connections` | HASH | `pid_connection_info_t` | `http2_conn_info_data_t` | H2 connection tracking |
| `outgoing_trace_map` | LRU_HASH | `egress_key_t{ports, stream_id}` | `tp_info_pid_t` | Per-stream sender trace context |
| `incoming_trace_map` | LRU_HASH | `connection_info_t` | `tp_info_pid_t` | Receiver trace context (TCP options) |
| `grpc_conn_ptr_to_conn` | LRU_HASH | `u64 (conn_ptr)` | `connection_info_t` | Go conn pointer → TCP ports |
