# gRPC/HTTP2 Context Propagation

Builds on the general [Context Propagation Architecture](context-propagation.md).

## Overview

Injects `traceparent` HPACK headers into outgoing HTTP/2 HEADERS frames and parses them on the receiving side.

**HPACK is the only network mechanism for gRPC/H2 CP.** TCP options are explicitly not used — see [Why not TCP options](#why-not-tcp-options).

Cross-process propagation is network-only.

## Egress

### sk_msg Injection Chain

```
obi_packet_extender
  └─ detect_h2           — find HEADERS frame, extract stream_id
       └─ find_existing   — check if traceparent already exists in HPACK
            └─ create_tp  — look up parent from outgoing_trace_map[{ports, stream_id}]
                 └─ write_tp — push 69 bytes of HPACK via bpf_msg_push_data
```

H2 detection: checks for `PRI *` preface or `sk_h2_conn_flag` socket storage (set on first detection, auto-freed on socket close). Scans up to 4 frames for HEADERS with `END_HEADERS`. PADDED/PRIORITY flags shrink the HPACK window inside the payload; `detect_h2` accounts for both.

`detect_h2` is resumable across tail calls via `tailcall_ctx.h2_scan_pos`. After `write_h2_tp` injects HPACK into a frame, it tail-calls `detect_h2` with `scan_pos` past the just-injected frame so multiplexed senders that batch multiple HEADERS frames into one `sendmsg` (Node grpc-js, Go loopyWriter under contention) get every stream injected. Bounded by `k_h2_max_frames_per_packet` (8) within the 33 tail-call budget.

Parent lookup priority in `create_tp`:

1. `outgoing_trace_map[{ports, stream_id}]` — written by Go uprobe or kprobe CLIENT
2. `find_parent_trace` — general fallback chain: Node.js → Python → nginx → Puma → Java → process traces → `cp_support_connect_info`

### Go Uprobe Path

1. **`transport_http2Client_NewStream`** — caches `conn_ptr → connection_info_t` in `grpc_conn_ptr_to_conn`
2. **`grpcFramerWriteHeaders`** — has both stream_id and trace context. Writes `outgoing_trace_map[{ports, stream_id}]`. Also marks the conn via `mark_go_grpc_client_conn` and injects traceparent via `bpf_probe_write_user` when `g_bpf_header_propagation` is true.

### sk_msg Bail for Go gRPC Conns

Once a conn is marked, `obi_packet_extender` (sk_msg) checks `is_go_grpc_client_conn` first: pulls the data, populates `msg_buffers` for the `tcp_sendmsg` kprobe, returns `SK_PASS`. No `detect_h2`, no TCP option scheduling. The per-stream `outgoing_trace_map` entry the uprobe wrote is preserved; the user-buffer HPACK on the wire carries the traceparent. HTTP/1 traffic from the same Go process is unmarked and goes through the HTTP/1 detection path.

## Ingress

- **kprobe HPACK parser** (`http2_grpc_start`, SERVER side): parses HPACK first (per-stream, immune to per-connection trace_map race on multiplexed streams), bounded to the actual frame payload length so trailing batched HEADERS aren't adopted, with PADDED/PRIORITY shrink applied. Falls back to `find_trace_for_server_request` only if HPACK parsing finds no traceparent
- **Go uprobe** (`http2Server_operateHeaders` + `server_handleStream`): writes parsed traceparent to `ongoing_grpc_server_stream_tps[{tr_ptr, stream_id}]`. `handleStream` reads per-stream first, falls back to the legacy `ongoing_grpc_transports` per-transport entry. Per-stream key avoids the last-writer-wins race when the same transport carries concurrent streams

## Parent Trace Linking

`outgoing_trace_map` is keyed by `egress_key_t = {s_port, d_port, stream_id}`. The `stream_id` isolates concurrent multiplexed streams on the same connection.

Writers:

- **Go uprobe** (`grpcFramerWriteHeaders`) — `BPF_ANY` with `written=1`, definitive trace from Go runtime
- **kprobe CLIENT** (`http2_grpc_start`) — `BPF_NOEXIST` with `written=0`, used only when no uprobe wrote first; span_id comes from `urand_bytes`
- **sk_msg** (`find_existing_h2_tp` / `create_h2_tp`) — `BPF_ANY`, used by non-Go senders. Persists the traceparent that was just written onto the wire so kprobe CLIENT can adopt the same context

`adopt_injected_trace`: called after `find_trace_for_client_request` in the kprobe CLIENT path. Overrides stale traces with whatever is in `outgoing_trace_map[{ports, stream_id}]`.

### Cleanup

`http2_grpc_end` (kprobe stream end) deletes `outgoing_trace_map[{ports, stream_id}]` for that stream. The connection-scoped `delete_client_trace_info` only clears the `stream_id=0` entry, so without per-stream cleanup the per-stream entries leak until LRU eviction.

## Why not TCP options

HTTP/1 CP uses TCP option kind 25 (`schedule_write_tcp_option` → sock_ops `write_hdr_cb`) as a robust per-connection channel for `trace_id`+`span_id`. gRPC/H2 deliberately does not.

**Multiplexing.** A single H2 connection carries many concurrent streams, each with its own trace context. TCP option kind 25 is **connection-scoped**: a single 24-byte payload carrying one `trace_id`+`span_id`. It cannot represent N distinct per-stream contexts. The first stream's context "wins" and all other streams on the same connection get the wrong context via TCP option. HPACK is per-frame and naturally per-stream.

**Enforcement.** `handle_existing_tp_pid` in `bpf/tpinjector/tpinjector.c` gates the TCP-option schedule on `!is_h2_socket(msg)`. The H2 tail-call chain (`detect_h2` → `find_existing_h2_tp` → `create_h2_tp` → `write_h2_tp`) never calls `schedule_write_tcp_option`. The Go gRPC bail (`is_go_grpc_client_conn`) also returns `SK_PASS` without scheduling.

## Known Limitations

### Persistent connections established before OBI

If a gRPC connection's HTTP/2 preface was sent before OBI attached, `ongoing_http2_connections` is never populated. The kprobe won't recognize subsequent frames as HTTP/2.

**Affected**: Non-Go services with persistent channels established at startup. Go services with uprobes are unaffected.

### Go lazy connect without uprobes

`grpc.NewClient` connects lazily on a background goroutine. Without Go uprobes (`OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=true`), `cp_support_connect_info` records the wrong thread and parent lookup fails.

**With uprobes**: Not affected.

### Two uprobes for the loopyWriter race — `executeAndPut` + `originateStream`

**The race.** When a Go gRPC client opens a new stream, two goroutines are involved:

1. The caller goroutine runs `NewStream`, which builds a `*headerFrame` and queues it on the `controlBuffer`.
2. The `loopyWriter` goroutine dequeues that `headerFrame`, assigns the HTTP/2 `stream_id`, and calls `framer.WriteHeaders`.

Our HPACK injection lives in `framer.WriteHeaders` and looks up the trace context in `ongoing_streams[{conn_ptr, stream_id}]`. That map is populated at `NewStream_ret` on the caller goroutine. But `loopyWriter` can run `WriteHeaders` *before* `NewStream` has returned — so for the first HEADERS frame the lookup misses and the trace context goes out without `traceparent`.

**Why two probes.**

- At `NewStream_ret` we know the trace context but not yet a usable stream_id (the stream isn't queued yet).
- At `WriteHeaders` we know the stream_id but we're on a different goroutine, so goroutine-keyed state from `NewStream` isn't visible.

We need a key both goroutines can agree on. The `*headerFrame` pointer fits: it's allocated by `NewStream` and passed all the way to `loopyWriter`.

**The bridge** (`bpf/gotracer/go_grpc.c`):

- **`(*controlBuffer).executeAndPut`** — runs on the caller goroutine just before the `headerFrame` is queued. Stashes the invocation in `pending_h2_invocations[hdr_ptr]`.
- **`(*loopyWriter).originateStream`** — runs on the loopyWriter goroutine just before `WriteHeaders`. By now `outStream.id` is assigned. Looks up the stash by `hdr_ptr`, then publishes `ongoing_streams[{conn_ptr, stream_id}]` so the existing `grpcFramerWriteHeaders` uprobe sees it.

## Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `sk_h2_conn_flag` | SK_STORAGE | socket | `u8` | Marks socket as HTTP/2 |
| `ongoing_http2_connections` | HASH | `pid_connection_info_t` | `http2_conn_info_data_t` | H2 connection tracking |
| `outgoing_trace_map` | LRU_HASH | `egress_key_t{ports, stream_id}` | `tp_info_pid_t` | Per-stream sender trace context |
| `incoming_trace_map` | LRU_HASH | `connection_info_t` | `tp_info_pid_t` | Receiver trace context (HTTP/1 path only; gRPC uses per-stream maps) |
| `grpc_conn_ptr_to_conn` | LRU_HASH | `u64 (conn_ptr)` | `connection_info_t` | Go conn pointer → TCP ports |
| `ongoing_grpc_server_stream_tps` | LRU_HASH | `stream_key_t{tr_ptr, stream_id}` | `tp_info_t` | Per-stream parsed traceparent (Go gRPC server) |
| `pending_h2_invocations` | LRU_HASH | `u64 (hdr ptr)` | `pending_h2_invocation_t{inv, conn_ptr}` | Two-hop bridge from `executeAndPut` to `originateStream` |
| `go_grpc_client_conns` | LRU_HASH | `pid_connection_info_t` | `u8` | Marks Go gRPC client conns (via `mark_go_grpc_client_conn`); sk_msg bails on `is_go_grpc_client_conn` hit |
