# Context Propagation Architecture

This document explains how OpenTelemetry context propagation works in the eBPF instrumentation, including the coordination between different injection layers and the mutual exclusion mechanism.

## Overview

Context propagation allows distributed tracing by injecting trace context (trace ID, span ID) into outgoing requests. The eBPF instrumentation supports multiple injection methods organized in a fallback hierarchy:

1. **HTTP headers** (L7) - `Traceparent:` header in plaintext HTTP requests
2. **TCP options** (L4) - Custom TCP option (kind 25) for any TCP traffic
3. **IP options** (L3) - IPv4 options or IPv6 Destination Options as fallback

## Configuration

Context propagation is controlled via `OTEL_EBPF_BPF_CONTEXT_PROPAGATION` which accepts a comma-separated list:

- `headers` - Inject HTTP headers
- `tcp` - Inject TCP options
- `ip` - Inject IP options
- `all` - Enable all methods (default)
- `disabled` - Disable context propagation

Examples:

- `headers,tcp` - HTTP headers for plaintext HTTP, TCP options otherwise
- `tcp,ip` - TCP options with IP options as fallback
- `tcp` - TCP options only

## Egress (Sending) Flow

### Execution Order

The order in which BPF programs execute varies depending on whether Go uprobes or SSL detection is involved:

#### Scenario A: Go HTTP or SSL/TLS (uprobes involved)

1. **uprobes** (Go HTTP client or SSL detection)
   - Populate `outgoing_trace_map` with initial trace context
   - Set `valid=1` for non-SSL, `valid=0` for SSL

2. **sk_msg (tpinjector)**
   - Runs for packets in sockmap
   - Can inject HTTP headers and/or schedule TCP options
   - Sets `written=1` when injection succeeds

3. **kprobe (tcp_sendmsg / protocol_http)**
   - Protocol detection and trace setup
   - Checks `written` flag to reuse trace info
   - Deletes from `outgoing_trace_map` if tpinjector handled it

4. **TC egress (tctracer)**
   - Injects IP options if not handled by upper layers
   - Checks `written` flag for mutual exclusion

#### Scenario B: Plain HTTP (no uprobes, kprobes only)

1. **sk_msg (tpinjector)**
   - Runs first for packets in sockmap
   - Protocol detector checks if HTTP
   - Can inject HTTP headers and/or schedule TCP options
   - Creates new trace info and sets `written=1`

2. **kprobe (tcp_sendmsg / protocol_http)**
   - Protocol detection and trace setup
   - Checks `written` flag - if set, reuses trace from tpinjector
   - Deletes from `outgoing_trace_map` if tpinjector handled it

3. **TC egress (tctracer)**
   - Injects IP options if not handled by upper layers
   - Checks `written` flag for mutual exclusion

#### Scenario C: Non-HTTP TCP (no uprobes, socket not in sockmap)

1. **kprobe (tcp_sendmsg)**
   - Creates trace info in `outgoing_trace_map`
   - Sets `valid=1, written=0`

2. **TC egress (tctracer)**
   - Sees `written=0`, injects IP options as fallback
   - Sets `valid=0` after injection

### Mutual Exclusion Mechanism

The `written` flag implements mutual exclusion through the natural execution order. The key principle: **only inject via one method per connection**.

#### Case 1: Traffic in sockmap with Go/SSL uprobes

**For SSL/TLS:**

```
1. Uprobe sets valid=0, written=0 in outgoing_trace_map
2. tpinjector (sk_msg) runs:
   - Schedules TCP options
   - Sees valid=0 (SSL), deletes outgoing_trace_map entry
3. protocol_http runs:
   - Lookup fails (entry deleted), skips
4. tctracer runs:
   - Lookup fails (entry deleted), no IP injection
Result: TCP options only ✓
```

**For Go HTTP (plaintext):**

Go supports two approaches for HTTP header injection:
- **Approach 1 (uprobe)**: Use `bpf_probe_write_user` to inject directly into Go's HTTP buffer
- **Approach 2 (sk_msg)**: Use tpinjector to extend the packet

The uprobe attempts approach 1 first. If successful, it deletes the `outgoing_trace_map` entry to prevent approach 2 from running:

```
1. uprobe_persistConnRoundTrip sets valid=1, written=0 in outgoing_trace_map
2. uprobe_writeSubset attempts bpf_probe_write_user:
   - If successful: deletes outgoing_trace_map entry
   - If failed: entry remains for tpinjector
3. tpinjector runs (only if entry still exists):
   - Schedules TCP options
   - Injects HTTP headers via sk_msg, sets written=1
4. protocol_http runs:
   - If written=1: reuses trace, deletes outgoing_trace_map
   - If written=0: creates new trace
5. tctracer runs:
   - If entry deleted: no IP injection
   - If entry exists with written=0: injects IP options
Result: HTTP headers (via uprobe OR sk_msg) + TCP options ✓
```

#### Case 2: Traffic in sockmap without uprobes (plain HTTP via kprobes)

**For plaintext HTTP with headers+tcp:**

```
1. tpinjector runs first:
   - Protocol detector identifies HTTP
   - Schedules TCP options
   - Injects HTTP headers
   - Creates trace, sets written=1, stores in outgoing_trace_map
2. protocol_http (kprobe) runs:
   - Sees written=1, reuses trace from tpinjector
   - Deletes outgoing_trace_map
3. tctracer runs:
   - Lookup fails (entry deleted), no IP injection
Result: HTTP headers + TCP options ✓
```

**For plaintext HTTP with tcp only:**

```
1. tpinjector runs first:
   - Protocol detector identifies HTTP
   - Schedules TCP options, sets written=1
   - Skips HTTP headers (inject_flags check)
   - Creates trace, stores in outgoing_trace_map
2. protocol_http (kprobe) runs:
   - Sees written=1, reuses trace from tpinjector
   - Deletes outgoing_trace_map
3. tctracer runs:
   - Lookup fails (entry deleted), no IP injection
Result: TCP options only ✓
```

#### Case 3: Traffic NOT in sockmap (tpinjector doesn't run)

**For any traffic:**

```
1. Kprobe sets valid=1, written=0 in outgoing_trace_map
2. tpinjector doesn't run (socket not in sockmap)
3. protocol_http runs:
   - Sees written=0, creates new trace
   - Does NOT delete outgoing_trace_map
4. tctracer runs:
   - Sees written=0, injects IP options
   - Sets valid=0 (done)
Result: IP options as fallback ✓
```

#### Case 4: TCP option injection fails

If `bpf_sk_storage_get()` fails in `schedule_write_tcp_option`, the function returns early **without setting written=1**. This allows IP options to be injected as fallback.

## Ingress (Receiving) Flow

### Execution Order

On ingress, the execution order is different:

1. **TC ingress (tctracer)** - Parses IP options first
2. **BPF_SOCK_OPS (tpinjector)** - Parses TCP options second
3. **kprobe (tcp_recvmsg / protocol_http)** - Parses HTTP headers last

### "Last One Wins" Strategy

Unlike egress (which uses mutual exclusion), ingress uses a **"last one wins"** approach:

1. **TC ingress** parses IP options (if present)
   - Extracts trace_id from IP options
   - Generates span_id from TCP seq/ack
   - Stores in `incoming_trace_map`

2. **BPF_SOCK_OPS** parses TCP options (if present)
   - Extracts trace_id and span_id from TCP option
   - **Overwrites** entry in `incoming_trace_map`

3. **protocol_http** parses HTTP headers (if present)
   - Extracts trace_id, span_id, flags from `Traceparent:` header
   - **Overwrites** previous values

This creates a natural priority hierarchy:

- **IP options**: Lowest priority (most likely to be stripped by middleboxes)
- **TCP options**: Medium priority (better reliability)
- **HTTP headers**: Highest priority (W3C standard, most reliable)

### Why "Last One Wins" on Ingress?

1. **Unknown sender behavior**: We don't control what the sender injected
2. **Natural priority**: Execution order matches reliability (most reliable parsed last)
3. **Handles redundancy**: If sender sent multiple methods, we automatically use the best one
4. **Simplicity**: No coordination logic needed between layers

## The outgoing_trace_map

`outgoing_trace_map` is a BPF map (type: `BPF_MAP_TYPE_HASH`) that coordinates context propagation between egress layers. It stores `tp_info_pid_t` structs keyed by connection info.

### tp_info_pid_t::valid (u8)

State machine tracking the injection lifecycle:

- **0**: Invalid/SSL (don't inject) OR injection complete (set by tctracer after IP injection)
- **1**: First packet seen, needs L4 span ID setup
- **2**: L4 span ID setup done, ready for injection

**Set to 0:**

- Go uprobes: SSL connections (`go_nethttp.c`)
- Kprobes: SSL connections (`trace_common.h`)
- tctracer: After successful IP option injection (`tctracer.c::encode_data_in_ip_options`)
- trace_common: Conflicting requests or timeouts (`trace_common.h`)

**Set to 1:**

- tpinjector: Creating new trace (`tpinjector.c::create_trace_info`)
- protocol_http: Creating new trace (`protocol_http.h::protocol_http`)
- protocol_tcp: Creating new trace (`protocol_tcp.h`)

**Set to 2:**

- tctracer: After populating span ID from TCP seq/ack (`tctracer.c::obi_app_egress`)

**Checked:**

- tpinjector: Skip protocol detection for SSL (`tpinjector.c::handle_existing_tp_pid`)
- tctracer: First packet handling and injection decision (`tctracer.c::obi_app_egress`)

### tp_info_pid_t::written (u8)

Coordination flag for mutual exclusion between egress injection layers:

- **0**: Not yet handled by tpinjector (sk_msg layer)
- **1**: Already handled by tpinjector (TCP options or HTTP headers injected)

**Purpose**: Implements the fallback hierarchy by preventing lower layers from injecting when higher layers already succeeded.

**Set to 0:**

- tpinjector: Initializing new trace (`tpinjector.c::create_trace_info`)
- protocol_http: Initializing new trace (`protocol_http.h::protocol_http`)
- Go uprobes: Creating client requests (`go_nethttp.c`)

**Set to 1:**

- tpinjector: After scheduling TCP options (`tpinjector.c::schedule_write_tcp_option`)
- tpinjector: After injecting HTTP headers (`tpinjector.c::write_http_traceparent`, `tpinjector.c::obi_packet_extender`)

**Checked:**

- protocol_http: Skip processing if tpinjector handled it (`protocol_http.h::protocol_http`)
- tctracer: Skip IP injection if upper layer handled it (`tctracer.c::obi_app_egress`)

**Key Behavior**: The `written` flag serves two purposes:

1. **protocol_http optimization**: Reuse existing trace info, avoid regenerating span IDs
2. **tctracer mutual exclusion**: Signal that upper layer already injected context

## The incoming_trace_map

`incoming_trace_map` is a BPF map (type: `BPF_MAP_TYPE_HASH`) that stores parsed trace context from incoming packets. It stores `tp_info_pid_t` structs keyed by connection info.

Unlike `outgoing_trace_map`, there is no coordination between layers - each layer independently parses and overwrites the map entry if context is found, implementing the "last one wins" strategy.

## Summary

1. **Egress uses mutual exclusion**:
   - Upper layers (tpinjector, protocol_http) delete the `outgoing_trace_map` entry
   - Lower layers (tctracer) can't inject if entry is already deleted
   - Result: Only one injection method per connection

2. **Ingress uses "last one wins"**:
   - Each layer independently parses if context is present
   - Later layers overwrite earlier layers
   - Result: Most reliable method takes precedence

3. **IP options are truly a fallback**:
   - On egress: Only injected when TCP options fail or socket isn't in sockmap
   - On ingress: Lowest priority, overwritten by TCP options or HTTP headers

4. **SSL/TLS uses TCP options, not HTTP headers**:
   - Can't inject into encrypted payload
   - TCP options work before TLS handshake
   - tpinjector deletes entry early to skip HTTP detection

5. **Execution order varies by scenario**:
   - Go/SSL: uprobes → tpinjector → kprobe → tctracer
   - Plain HTTP (sockmap): tpinjector → kprobe → tctracer
   - Non-sockmap: kprobe → tctracer
