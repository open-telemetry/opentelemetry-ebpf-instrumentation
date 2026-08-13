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

The scan recognizes the encodings that put identifying bytes on the wire: a literal name in any of the three literal prefixes, plain or huffman, and a dyn-table name reference whose value is plain (`0x37` + `00-` + dash positions). On egress a compressed value still counts only as *present*, not adoptable; ingress decodes it.

Some encodings leave nothing at all: a dyn-table name reference with a compressed value, or — when a sender repeats the *same* traceparent — a single index byte standing for the whole field. The generic socket path therefore keeps its conservative connection latch for non-Go senders. Go HTTP/2 and grpc-go use the pre-serialization ownership path below instead; their decision is exact per stream and does not rely on wire bytes or dynamic-table history.

Parent lookup priority in `create_tp`:

1. exact Go stream state, then `outgoing_trace_map[{ports, stream_id}]` for non-Go senders
2. `find_parent_trace` — general fallback chain: Node.js → Python → nginx → Puma → Java → process traces → `cp_support_connect_info`

### Go Uprobe Path

Go HTTP/2 and grpc-go publish a directional key containing PID, process start time, both addresses and ports, and the HTTP/2 stream ID. The process identity prevents a reused PID from adopting an earlier process's state. The value records whether the application supplied `traceparent`, OBI may inject, OBI committed a write, or the request must fail closed.

- net/http's vendored HTTP/2 client and `golang.org/x/net/http2` observe each field at `ClientConn.writeHeader`, before HPACK serialization. `writeHeaders` supplies the stream ID and connection, and `Framer.endWrite` provides entry and pre-`Writer.Write` commit points.
- grpc-go bridges the caller and loopy-writer goroutines with the `headerFrame` pointer at `controlBuffer.executeAndPut`. The version-appropriate `headerHandler` or `clientHeaderHandler` supplies the stream ID. `hpack.Encoder.WriteField` then observes application metadata before serialization, and `Framer.endWrite` commits before its underlying writer can consume the frame.

Probe sets attach atomically for each library family. Missing symbols or a missing pre-write boundary disable the whole ownership path for that family instead of leaving partial state. Before Go appends a small final `HEADERS` payload, OBI reserves 69 bytes of RFC-valid padding and converts it into the HPACK traceparent at `endWrite` entry. Go therefore allocates the memory itself, including on the first unbuffered TLS request. An interior source boundary immediately before `Writer.Write` handles a full final `HEADERS` or `CONTINUATION` by appending a separate continuation frame. User-memory updates are read back, and both the writer length and frame metadata are restored and verified after a failed transaction.

### sk_msg Per-Stream Fallback for Go gRPC Conns

The socket injector consults exact Go stream state before scanning HPACK or applying the generic socket latch. Application-owned, committed, and fail-closed streams are never modified. A pending stream bypasses the wire ownership scan and uses the exact stored OBI context, so an indexed application field on a different stream cannot suppress it. A marked Go connection with missing or stale exact state fails closed.

Socket mutation is transactional: frame length is changed, space is pushed, HPACK bytes and both metadata updates are read back, and the state changes to written only after every check succeeds. Failures pop the bytes and restore the old frame length; an unverified rollback changes the stream to fail-closed. Kernels without `bpf_msg_pop_data` load a separate program that performs no HTTP/2 socket mutation. TLS ciphertext never reaches the confirmed HTTP/2 path.

The socket fallback can only rewrite a complete HTTP/2 frame present in one
`sk_msg` buffer. If a missed uprobe leaves a large `HEADERS` or `CONTINUATION`
frame split across socket callbacks, the fallback fails closed because its
length field may already be on the wire. Normal Go instrumentation injects at
the user buffer before this split; the socket fallback remains best effort for
missed probes and pre-existing connections.

## Ingress

- **kprobe HPACK parser** (`http2_grpc_start`, SERVER side): parses HPACK first (per-stream, immune to per-connection trace_map race on multiplexed streams), bounded to the actual frame payload length so trailing batched HEADERS aren't adopted, with PADDED/PRIORITY shrink applied. Falls back to `find_trace_for_server_request` only if HPACK parsing finds no traceparent. Requests 2+ on a persistent connection carry `traceparent` as an HPACK dyn-table indexed name — no literal name on the wire — so the server finalize stage additionally runs `find_hpack_traceparent_value` (value fingerprint: `0x37` length byte + `00-` prefix + dash positions + hex spot-checks). That scan lives in its own tail-call program (`..._server_finalize` → `..._server_commit`, jump table slot 14): sharing a program with the commit body exceeds the verifier's 1M-instruction ceiling on kernels 6.12+
- **Huffman values**: SDKs usually huffman-compress the traceparent value — 35 octets on the wire instead of 55 — so none of the plain-text scans above can read it. Decoding is cheap because the traceparent alphabet is tiny: every character it can contain (`0-9a-f-`) has a 5- or 6-bit code in RFC 7541 Appendix B, so reading 6 bits is always enough to identify the next character, and `h2_tp_huffman.h` does exactly that with a single 64-entry lookup table. The table doubles as the validator: 41 of its slots name no traceparent character, so decoding anything else hits an empty slot and rejects. The EOS prefix lands on slot `0x3f`, so encoded EOS rejects the same way.

  The work spans three stages because a decode loop nested inside the HPACK scan is too much for one BPF program:

  1. The scan only *records* where a compressed value sits (`h2_tp_huff_candidate_t`).
  2. `..._server_huffman` (jump table slot 15) decodes it with `bpf_loop`.
  3. `..._server_huffscan` (slot 16) covers the indexed-name case: a dyn-table name reference leaves no name on the wire to match, so this program sweeps the block for a plausible compressed value on its own. Its verdict ranks above `find_trace_for_server_request` — a successful decode is self-validating — while the weaker plain value fingerprint in finalize stays below it.

  `bpf_loop` puts the feature's kernel floor at **5.17**. On older kernels `g_bpf_loop_enabled` is false, the decode never runs, and ingress keeps its existing fallbacks.
- **Go uprobe** (`http2Server_operateHeaders` + `server_handleStream`): writes parsed traceparent to `ongoing_grpc_server_stream_tps[{tr_ptr, stream_id}]`. `handleStream` reads per-stream first, falls back to the legacy `ongoing_grpc_transports` per-transport entry. Per-stream key avoids the last-writer-wins race when the same transport carries concurrent streams

## Parent Trace Linking

`outgoing_trace_map` is keyed by `egress_key_t = {s_port, d_port, stream_id}`. The `stream_id` isolates concurrent multiplexed streams on the same connection.

Writers:

- **Go uprobes** — publish only the exact PID/process/connection/stream state. They do not write the weak port-only map.
- **kprobe CLIENT** (`http2_grpc_start`) — `BPF_NOEXIST` with `written=0`, used only when no uprobe wrote first; span_id comes from `urand_bytes`
- **sk_msg** (`find_existing_h2_tp` / `create_h2_tp`) — `BPF_ANY`, used by non-Go senders. Persists the traceparent that was just written onto the wire so kprobe CLIENT can adopt the same context

`adopt_injected_trace`: called after `find_trace_for_client_request` in the kprobe CLIENT path. It adopts a committed exact Go stream first. The PID-checked `outgoing_trace_map[{ports, stream_id}]` fallback is used only when neither exact stream state nor a fresh semantic Go connection marker exists.

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

### Two stages for the loopyWriter race

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
- **`(*loopyWriter).headerHandler` / `clientHeaderHandler`** — runs on the loopyWriter goroutine after the stream ID is assigned. It looks up the stash by `hdr_ptr`, then publishes the exact directional stream state before HPACK encoding begins.

## Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `sk_h2_conn_flag` | SK_STORAGE | socket | `u8` | Marks socket as HTTP/2 |
| `ongoing_http2_connections` | HASH | `pid_connection_info_t` | `http2_conn_info_data_t` | H2 connection tracking |
| `outgoing_trace_map` | LRU_HASH | `egress_key_t{ports, stream_id}` | `tp_info_pid_t` | Per-stream sender trace context |
| `incoming_trace_map` | LRU_HASH | `connection_info_t` | `tp_info_pid_t` | Receiver trace context (HTTP/1 path only; gRPC uses per-stream maps) |
| `grpc_conn_ptr_to_conn` | LRU_HASH | `go_addr_key_t{pid, conn_ptr}` | `connection_info_t` | Go conn pointer → directional TCP connection |
| `ongoing_grpc_server_stream_tps` | LRU_HASH | `stream_key_t{tr_ptr, stream_id}` | `tp_info_t` | Per-stream parsed traceparent (Go gRPC server) |
| `pending_h2_invocations` | LRU_HASH | `go_addr_key_t{pid, hdr ptr}` | `pending_h2_invocation_t{tp, request, conn_ptr}` | Bridge from `executeAndPut` to the loopy-writer header handler |
| `go_h2_stream_states` | LRU_HASH | `{pid, process start, directional conn, stream_id}` | `go_h2_stream_value_t` | Exact application/OBI ownership and fallback state |
| `go_h2_client_conns` | LRU_HASH | `{pid, process start, directional conn}` | `go_h2_conn_value_t` | Fresh directional marker; missing exact stream state fails closed |

Exact stream entries are deleted when the HTTP/2 header encoder or gRPC client request completes. Pending cross-goroutine entries are deleted on queue errors, handler consumption, and LRU eviction. Connection markers and all values carry a 30-second freshness bound, which limits missed-return, process-exit, and PID/pointer-reuse residue in addition to LRU eviction.
