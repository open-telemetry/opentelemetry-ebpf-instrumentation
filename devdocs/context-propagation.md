# Context Propagation Architecture

This document explains how OpenTelemetry context propagation works in the eBPF instrumentation, including the coordination between different injection layers and the mutual exclusion mechanism.

## Table Of Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [Egress (Sending) Flow](#egress-sending-flow)
  - [Execution Order](#execution-order)
    - [Scenario A: Go HTTP or SSL/TLS (uprobes involved)](#scenario-a-go-http-or-ssltls-uprobes-involved)
    - [Scenario B: Plain HTTP (no uprobes, kprobes only)](#scenario-b-plain-http-no-uprobes-kprobes-only)
    - [Scenario C: Non-HTTP TCP (no uprobes, socket not in sockmap)](#scenario-c-non-http-tcp-no-uprobes-socket-not-in-sockmap)
  - [Mutual Exclusion Mechanism](#mutual-exclusion-mechanism)
    - [Case 1: Traffic in sockmap with Go/SSL uprobes](#case-1-traffic-in-sockmap-with-gossl-uprobes)
    - [Case 2: Traffic in sockmap without uprobes (plain HTTP via kprobes)](#case-2-traffic-in-sockmap-without-uprobes-plain-http-via-kprobes)
    - [Case 3: Traffic NOT in sockmap (tpinjector doesn't run)](#case-3-traffic-not-in-sockmap-tpinjector-doesnt-run)
- [Ingress (Receiving) Flow](#ingress-receiving-flow)
  - [Execution Order](#execution-order-1)
  - ["Last One Wins" Strategy](#last-one-wins-strategy)
  - [Why "Last One Wins" on Ingress?](#why-last-one-wins-on-ingress)
- [The outgoing_trace_map](#the-outgoing_trace_map)
  - [tp_info_pid_t::valid (u8)](#tp_info_pid_tvalid-u8)
  - [tp_info_pid_t::written (u8)](#tp_info_pid_twritten-u8)
- [The incoming_trace_map](#the-incoming_trace_map)
- [The sock_dir sockmap](#the-sock_dir-sockmap)
- [Summary](#summary)
- [Logs correlation](#logs-correlation)

## Overview

Context propagation allows distributed tracing by injecting trace context (trace ID, span ID) into outgoing requests. The eBPF instrumentation supports two injection methods:

1. **HTTP headers** (L7) - `Traceparent:` header in plaintext HTTP requests
2. **TCP options** (L4) - Custom TCP option (kind 25) for any TCP traffic

## Configuration

Context propagation is controlled via `OTEL_EBPF_BPF_CONTEXT_PROPAGATION` which accepts a comma-separated list:

- `headers` - Inject HTTP headers
- `tcp` - Inject TCP options
- `all` - Enable all methods (default)
- `disabled` - Disable context propagation

Examples:

- `headers,tcp` - HTTP headers for plaintext HTTP, TCP options otherwise
- `tcp` - TCP options only
- `headers` - HTTP headers only

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

#### Scenario C: Non-HTTP TCP (no uprobes, socket not in sockmap)

1. **kprobe (tcp_sendmsg)**
   - Creates trace info in `outgoing_trace_map`
   - Sets `valid=1, written=0`

Note: tpinjector does not run for this traffic because the socket was not in `sock_dir`. The `iter/tcp` iterator pre-populates `sock_dir` at startup for existing connections; new connections are added via `BPF_SOCK_OPS`.

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
Result: TCP options only ✓
```

#### Case 3: Traffic NOT in sockmap (tpinjector doesn't run)

```
1. Kprobe sets valid=1, written=0 in outgoing_trace_map
2. tpinjector doesn't run (socket not in sockmap)
3. protocol_http runs:
   - Sees written=0, creates new trace
Result: no context propagation for this connection ✓
```

## Ingress (Receiving) Flow

### Execution Order

On ingress, the execution order is:

1. **BPF_SOCK_OPS (tpinjector)** - Parses TCP options
2. **kprobe (tcp_recvmsg / protocol_http)** - Parses HTTP headers

### "Last One Wins" Strategy

Unlike egress (which uses mutual exclusion), ingress uses a **"last one wins"** approach:

1. **BPF_SOCK_OPS** parses TCP options (if present)
   - Extracts trace_id and span_id from TCP option
   - Stores in `incoming_trace_map`

2. **protocol_http** parses HTTP headers (if present)
   - Extracts trace_id, span_id, flags from `Traceparent:` header
   - **Overwrites** previous values

This creates a natural priority hierarchy:

- **TCP options**: Lower priority
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

- **0**: Invalid/SSL (don't inject)
- **1**: First packet seen, needs L4 span ID setup
- **2**: L4 span ID setup done, ready for injection

**Set to 0:**

- Go uprobes: SSL connections (`go_nethttp.c`)
- Kprobes: SSL connections (`trace_common.h`)
- trace_common: Conflicting requests or timeouts (`trace_common.h`)

**Set to 1:**

- tpinjector: Creating new trace (`tpinjector.c::create_trace_info`)
- protocol_http: Creating new trace (`protocol_http.h::protocol_http`)
- protocol_tcp: Creating new trace (`protocol_tcp.h`)

**Set to 2:**

- tpinjector: After populating span ID from TCP seq/ack

**Checked:**

- tpinjector: Skip protocol detection for SSL (`tpinjector.c::handle_existing_tp_pid`)

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

## The incoming_trace_map

`incoming_trace_map` is a BPF map (type: `BPF_MAP_TYPE_HASH`) that stores parsed trace context from incoming packets. It stores `tp_info_pid_t` structs keyed by connection info.

Unlike `outgoing_trace_map`, there is no coordination between layers - each layer independently parses and overwrites the map entry if context is found, implementing the "last one wins" strategy.

## The sock_dir sockmap

`sock_dir` is a `BPF_MAP_TYPE_SOCKHASH` map keyed by `u64` socket cookie. It controls which sockets the `sk_msg` program (tpinjector) runs on.

Sockets are added to `sock_dir` in two ways:

1. **`BPF_SOCK_OPS`**: New connections are added automatically as they are established
2. **`iter/tcp` iterator** (`bpf/tpinjector/sock_iter.c`): Runs at tpinjector startup and iterates over all existing TCP sockets, inserting each into `sock_dir` with `BPF_NOEXIST`. This ensures connections established before tpinjector attached are tracked.

## Summary

1. **Egress uses mutual exclusion**:
   - Upper layers (tpinjector, protocol_http) delete the `outgoing_trace_map` entry
   - Lower layers can't inject if entry is already deleted
   - Result: Only one injection method per connection

2. **Ingress uses "last one wins"**:
   - Each layer independently parses if context is present
   - Later layers overwrite earlier layers
   - Result: Most reliable method takes precedence

3. **SSL/TLS uses TCP options, not HTTP headers**:
   - Can't inject into encrypted payload
   - TCP options work before TLS handshake
   - tpinjector deletes entry early to skip HTTP detection

4. **Execution order varies by scenario**:
   - Go/SSL: uprobes → tpinjector → kprobe
   - Plain HTTP (sockmap): tpinjector → kprobe
   - Non-sockmap: kprobe only

## Logs correlation

OBI allows injecting trace context into JSON logs. The following requirements must be met:

- Linux kernel version **6.0 or later** (overwriting user memory requires a `UBUF`-type `iov_iter`)
- `CAP_SYS_ADMIN` capability and permission to use `bpf_probe_write_user` (kernel security lockdown mode should be `[none]`)
- The target application writes logs in **JSON format**
- BPFFS mounted at /sys/fs/bpf (or another mountpath configurable via `config.ebpf.bpf_fs_path`)
- Async primitives: only Go runtime is currently supported
