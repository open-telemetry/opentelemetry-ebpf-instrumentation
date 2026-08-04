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

H2 detection: the `sk_h2_conn_flag` socket storage holds a state machine (`none → preface → confirmed | rejected`, auto-freed on socket close). A `PRI *` preface followed by SETTINGS confirms; a non-SETTINGS first frame rejects (yamux protection, #2734). Connections whose preface predates OBI attachment can never see a preface, so `wrap_http2_traceparent` runs a strict RFC 7540 mid-stream sniff (`h2_sniff_*` in `h2_defs.h`): frames must tile the buffer exactly, HEADERS on an odd stream, per-type flag/length rules, and every HEADERS block must open with a pseudo-header. A sniff pass sets `confirmed` directly. Response blocks pass the sniff and latch `k_h2_sk_server`: the socket is HTTP/2 either way, and rejecting it there would leave every server-side connection re-sniffing on every packet. Whether the frame may be injected is a separate question, answered by `h2_inject_verdict`. Connections the generic tracer tracked as SSL are never sniffed — a false positive would splice HPACK into ciphertext. Scans up to 4 frames for HEADERS with `END_HEADERS`. PADDED/PRIORITY flags shrink the HPACK window inside the payload; `detect_h2` accounts for both.

`detect_h2` is resumable across tail calls via `tailcall_ctx.h2_scan_pos`. After `write_h2_tp` injects HPACK into a frame, it tail-calls `detect_h2` with `scan_pos` past the just-injected frame so multiplexed senders that batch multiple HEADERS frames into one `sendmsg` (Node grpc-js, Go loopyWriter under contention) get every stream injected. Bounded by `k_h2_max_frames_per_packet` (5) within the 33 tail-call budget: 5 hops per frame plus 2 per HPACK scan retry, `1 + 5*5 + 2*2 = 30`.

Before injecting, `h2_inject_verdict` (`tpinjector/inject_policy.h`) decides eligibility from the frame's opener byte, the socket direction, the Go uprobe handshake and what the HPACK scan found. Both `detect_h2` (direction) and `create_h2_tp` (content) call it, so the two stages cannot disagree. The opener is the first HPACK *field* byte — any leading dynamic table size updates (RFC 7541 6.3, emitted whenever the peer advertises `SETTINGS_HEADER_TABLE_SIZE`) are skipped first, otherwise a legal request block reads as "not a request".

Injection requires *proving* the block carries no traceparent, not merely failing to find one: a second field makes receivers discard both. `k_h2_skip_unscanned` covers a block longer than `k_h2_max_hpack_scan` and a scan that ran out of retries.

The scan recognizes the encodings that put identifying bytes on the wire: a literal name in any of the three literal prefixes, plain or huffman, and a dyn-table name reference whose value is plain (`0x37` + `00-` + dash positions).

Some encodings leave nothing at all: a dyn-table name reference with a compressed value, or — when a sender repeats the *same* traceparent, as a service fanning one incoming context out to several downstream calls — a single index byte standing for the whole field. Measured on grpc-js: request 1 is a 74-byte block holding `40 88 <huffman traceparent> a5 <huffman value>`, requests 2-4 are 25 bytes with no trace of it.

No content scan can see those, and none needs to. An index only exists because the encoder inserted the entry, and at insertion time the name was on the wire in full — so matching the name once and latching `k_h2_sk_app_tp` on the socket covers every later reference to it exactly, with no table state and no guesswork. OBI then stands down on that socket for good.

Two consequences follow, and both are properties of the rule rather than gaps in it. A socket shared between callers that propagate and callers that do not loses injection for the quiet ones — chosen deliberately, since a second field voids the header for the whole downstream chain. And a connection whose insertions predate attachment has a table OBI never watched being built, so a traceparent already reduced to an index there is invisible; that case is bounded by `k_h2_skip_unscanned` only when the block is too long to walk, not when it is short and opaque.

Parent lookup priority in `create_tp`:

1. `outgoing_trace_map[{ports, stream_id}]` — written by Go uprobe or kprobe CLIENT
2. `find_parent_trace` — general fallback chain: Node.js → Python → nginx → Puma → Java → process traces → `cp_support_connect_info`

### Go Uprobe Path

1. **`transport_http2Client_NewStream`** — caches `conn_ptr → connection_info_t` in `grpc_conn_ptr_to_conn`
2. **`grpcFramerWriteHeaders`** — has both stream_id and trace context. Writes `outgoing_trace_map[{ports, stream_id}]`. Also marks the conn via `mark_go_grpc_client_conn` and injects traceparent via `bpf_probe_write_user` when `g_bpf_header_propagation` is true.

### sk_msg Per-Stream Fallback for Go gRPC Conns

Once a conn is marked, `obi_packet_extender` (sk_msg) checks `is_go_grpc_client_conn` first: pulls the data, populates `msg_buffers` for the `tcp_sendmsg` kprobe, sets `tailcall_ctx.go_grpc_conn` and tail-calls `detect_h2`. No TCP option scheduling. Per stream, the chain then honors the `written` handshake: `written=1` means the uprobe's user-buffer HPACK carries the traceparent — skip the frame; `written=0` means the uprobe write failed or went unconfirmed — the wire scan adopts an on-wire traceparent if one is found, otherwise `create_h2_tp` injects the stored tp. Streams with no stored tp at all are never touched on a Go conn (`go_grpc_conn` guard). Since `originateStream` publishes a tp for every client stream, that guard rarely fires now; TLS is kept out by the socket state machine instead — ciphertext has no preface and cannot pass the mid-stream sniff, so `detect_h2` never runs on it. HTTP/1 traffic from the same Go process is unmarked and goes through the HTTP/1 detection path.

## Ingress

- **kprobe HPACK parser** (`http2_grpc_start`, SERVER side): parses HPACK first (per-stream, immune to per-connection trace_map race on multiplexed streams), bounded to the actual frame payload length so trailing batched HEADERS aren't adopted, with PADDED/PRIORITY shrink applied. Falls back to `find_trace_for_server_request` only if HPACK parsing finds no traceparent. Requests 2+ on a persistent connection carry `traceparent` as an HPACK dyn-table indexed name — no literal name on the wire — so the server finalize stage additionally runs `find_hpack_traceparent_value` (value fingerprint: `0x37` length byte + `00-` prefix + dash positions + hex spot-checks). That scan lives in its own tail-call program (`..._server_finalize` → `..._server_commit`, jump table slot 14): sharing a program with the commit body exceeds the verifier's 1M-instruction ceiling on kernels 6.12+
- **Go uprobe** (`http2Server_operateHeaders` + `server_handleStream`): writes parsed traceparent to `ongoing_grpc_server_stream_tps[{tr_ptr, stream_id}]`. `handleStream` reads per-stream first, falls back to the legacy `ongoing_grpc_transports` per-transport entry. Per-stream key avoids the last-writer-wins race when the same transport carries concurrent streams

## Parent Trace Linking

`outgoing_trace_map` is keyed by `egress_key_t = {s_port, d_port, stream_id}`. The `stream_id` isolates concurrent multiplexed streams on the same connection.

Writers:

- **Go uprobes** (`loopyWriter.originateStream` + `grpcFramerWriteHeaders` entry) — `BPF_ANY` with `written=0`; the `WriteHeaders` return probe flips it to `written=1` only after every `bpf_probe_write_user` landed and `n == off + 9 + frame_len` still holds (a mid-write flush or CONTINUATION split moved the frame — patching then would corrupt the stream, so sk_msg injects instead)
- **kprobe CLIENT** (`http2_grpc_start`) — `BPF_NOEXIST` with `written=0`, used only when no uprobe wrote first; span_id comes from `urand_bytes`
- **sk_msg** (`find_existing_h2_tp` / `create_h2_tp`) — `BPF_ANY`, used by non-Go senders. Persists the traceparent that was just written onto the wire so kprobe CLIENT can adopt the same context

`adopt_injected_trace`: called after `find_trace_for_client_request` in the kprobe CLIENT path. Overrides stale traces with whatever is in `outgoing_trace_map[{ports, stream_id}]`.

### Cleanup

`http2_grpc_end` (kprobe stream end) deletes `outgoing_trace_map[{ports, stream_id}]` for that stream. The connection-scoped `delete_client_trace_info` only clears the `stream_id=0` entry, so without per-stream cleanup the per-stream entries leak until LRU eviction.

## Why not TCP options

HTTP/1 CP uses TCP option kind 25 (`schedule_write_tcp_option` → sock_ops `write_hdr_cb`) as a robust per-connection channel for `trace_id`+`span_id`. gRPC/H2 deliberately does not.

**Multiplexing.** A single H2 connection carries many concurrent streams, each with its own trace context. TCP option kind 25 is **connection-scoped**: a single 24-byte payload carrying one `trace_id`+`span_id`. It cannot represent N distinct per-stream contexts. The first stream's context "wins" and all other streams on the same connection get the wrong context via TCP option. HPACK is per-frame and naturally per-stream.

**Enforcement.** `handle_existing_tp_pid` in `bpf/tpinjector/tpinjector.c` gates the TCP-option schedule on `!is_h2_socket(msg)`. The H2 tail-call chain (`detect_h2` → `find_existing_h2_tp` → `create_h2_tp` → `write_h2_tp`) never calls `schedule_write_tcp_option`, and the Go gRPC branch (`is_go_grpc_client_conn`) enters that chain directly, also without scheduling.

## Known Limitations

### Method names on pre-existing non-Go connections

Connections established before OBI attached are recognized (mid-stream sniff), produce spans, and propagate context — but on non-Go services the span name degrades to `*`. Requests 2+ on a persistent connection encode `:path` as a bare HPACK dynamic-table index; the literal string crossed the wire only in a request sent before attach, so no wire observer can recover it. The userspace per-connection HPACK mirror (`bhpack`, one decoder per direction in `http2grpc_transform.go`) resolves indices only for connections observed from their first byte — attaching mid-stream, its insertion history diverges from the peer's real table, so even post-attach literals cannot safely resolve later indexed references and the decoder refuses rather than guesses.

`traceparent` is unaffected (sk_msg re-injects the value literally on every request, and the server-side value-fingerprint scan recovers it). Go services are unaffected (uprobes read the method from process memory).

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
