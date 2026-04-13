# Trace-Log Correlation

OBI can enrich JSON log lines with `trace_id` and `span_id` fields, linking logs to the distributed trace that produced them.

## Table Of Contents

- [Overview](#overview)
- [The `traces_ctx_v1` map](#the-traces_ctx_v1-map)
- [The context staleness problem](#the-context-staleness-problem)
- [Per-runtime context refresh](#per-runtime-context-refresh)
  - [Go — uprobe entry + `runtime.casgstatus` uprobe](#go--uprobe-entry--runtimecasgstatus-uprobe)
  - [Node.js — `async_hooks` before callback + `uv_fs_access` uprobe](#nodejs--async_hooks-before-callback--uv_fs_access-uprobe)
  - [Java — `k_ioctl_java_threads` in the ioctl kprobe](#java--k_ioctl_java_threads-in-the-ioctl-kprobe)
  - [Ruby (Puma) — `rb_ary_shift` uprobe](#ruby-puma--rb_ary_shift-uprobe)
- [Requirements](#requirements)

## Overview

The logenricher hooks into write paths (`tty_write`, `pipe_write`, `ksys_write`, `do_writev`) to intercept log output. When a write occurs it:

1. Looks up `traces_ctx_v1[pid_tgid]` to get the active trace/span context for the calling thread.
2. Reads the user buffer via `bpf_probe_read_user`, packages the log line together with the trace context into a `log_event_t`, and submits it to the `log_events` ring buffer.
3. Overwrites the original user buffer with zeros via `bpf_probe_write_user` to suppress the un-enriched line.
4. User-space reads from the ring buffer and re-emits the log with `trace_id`/`span_id` injected into the JSON.

Because the original user buffer is zeroed out (step 3), the container log file will contain NULL characters in place of the original log line. This is expected — the enriched line is written separately by user-space, and the NULLs prevent the container runtime from capturing the un-enriched duplicate.

Both `ITER_UBUF` (kernel ≥ 6.0, used by `write()`) and `ITER_IOVEC` (all kernel versions, used by `writev()`) iterator types are supported. The `do_writev` kprobe captures the fd for `writev()` calls so `pipe_write` can resolve the file descriptor (registered as non-required — if the symbol isn't available, `write()`-based enrichment still works).

## The `traces_ctx_v1` map

`traces_ctx_v1` is a **pinned** `LRU_HASH` map shared across all BPF programs:

- **Key**: `u64 pid_tgid` — the combined PID and TID of the calling thread
- **Value**: `obi_ctx_info_t` — `trace_id[16]` + `span_id[8]`
- **Pinning**: `LIBBPF_PIN_BY_NAME` under `<bpf_fs_path>/otel/` (default `bpf_fs_path` is `/sys/fs/bpf`, configurable via `config.ebpf.bpf_fs_path` / `OTEL_EBPF_BPF_FS_PATH`).

The map is **written** by the generic tracer (in `server_or_client_trace()`) whenever an HTTP request or client call is detected on the wire. The map is **read** by the logenricher when intercepting writes.

## The context staleness problem

`traces_ctx_v1` is keyed by OS-level `pid_tgid`. This works when the thread that receives the HTTP data is the same thread that writes the log. But many runtimes decouple I/O from processing:

- **Go**: Goroutines are multiplexed onto OS threads (M's). A goroutine can resume on a different M after being descheduled.
- **Node.js**: The single-threaded event loop can read data for multiple in-flight requests (via libuv) before invoking any JS callback, overwriting `traces_ctx_v1` each time.
- **Java**: HTTP servers (Tomcat, Netty) use thread pools. The acceptor thread receives the data, but a worker thread from the pool processes the request and writes logs.
- **Ruby (Puma)**: When all workers are busy, the reactor thread reads HTTP data (setting context for itself), then hands off to a worker that has no context.

Without correction, `traces_ctx_v1[pid_tgid]` may carry the wrong trace context when a log is written. Each runtime has a dedicated mechanism to refresh the map at the right moment.

## Per-runtime context refresh

### Go — uprobe entry + `runtime.casgstatus` uprobe

Go's context refresh has two complementary mechanisms:

**1. Immediate set at uprobe entry**: Each Go protocol uprobe (HTTP `ServeHTTP`, gRPC `server_handleStream`, Redis `redis_process`, etc.) calls `obi_ctx__set(bpf_get_current_pid_tgid(), &tp)` immediately after storing the invocation in its per-goroutine map. This ensures `traces_ctx_v1` is populated from the very start of the handler, so log writes that happen before any goroutine reschedule are enriched.

**2. Refresh on goroutine status transitions**: The Go runtime calls `runtime.casgstatus` on every goroutine status transition. OBI hooks this function and, when a goroutine transitions to `g_running` (2) or `g_syscall` (3), looks up the goroutine's active operation (HTTP server, gRPC, Kafka, SQL, etc.) and calls `obi_ctx__set(pid_tgid, &tp)`. This fires on every context switch, so `traces_ctx_v1` stays in sync when a goroutine migrates to a different OS thread.

**3. Cleanup at return uprobes**: When the handler returns, the return uprobe deletes the per-goroutine map entry and calls `obi_ctx__del(pid_tgid)` to remove stale context from `traces_ctx_v1`.

**Why setting context at uprobe entry is safe**: At the moment the uprobe fires (e.g. `ServeHTTP`), the goroutine is guaranteed to be running on the current OS thread — `bpf_get_current_pid_tgid()` returns the correct `pid_tgid`. The `traces_ctx_v1` map uses `BPF_ANY` semantics, so the write is idempotent: the subsequent `casgstatus` transition will overwrite the entry with the same trace/span IDs. If the goroutine migrates to a different OS thread later, `casgstatus` handles the update for the new `pid_tgid`, and the `default` branch deletes the stale entry for the old one.

### Node.js — `async_hooks` before callback + `uv_fs_access` uprobe

The JS agent installs an `async_hooks` `createHook({ before() { ... } })`. Before each async callback executes, the hook calls `fs.accessSync('/dev/null/obi-ctx/<incomingFd>')`. This triggers the `obi_uv_fs_access` uprobe in BPF, which:

1. Parses the 4-digit fd from the path.
2. Looks up `fd_to_connection[pid_tgid, fd]` to get the connection info.
3. Calls `trace_info_for_connection(conn, TRACE_TYPE_SERVER)` to find the server trace.
4. Calls `obi_ctx__set(pid_tgid, &tp)` or `obi_ctx__del(pid_tgid)`.

This fires before every JS callback, ensuring the correct trace context is active even when multiple requests are interleaved in the event loop.

### Java — `k_ioctl_java_threads` in the ioctl kprobe

The Java agent uses ByteBuddy to intercept `Executor.execute()`, `Runnable.run()`, `Callable.call()`, and `ForkJoinTask` methods. When a task starts executing on a worker thread, `ThreadInfo.sendParentThreadContext(parentId)` sends an `ioctl(0, 0x0b10b1, packet)` with operation type `k_ioctl_java_threads` (3).

The BPF kprobe handler:

1. Updates `java_tasks[child_tid] = parent_tid` (thread hierarchy map).
2. Walks the `java_tasks` chain (up to 3 levels) looking up `server_traces` for each ancestor.
3. If a valid server trace is found, calls `obi_ctx__set(child_pid_tgid, &tp)`. Otherwise calls `obi_ctx__del`.

Unlike Node.js (which refreshes before every callback), Java only needs to refresh once when the task starts — Java threads don't multiplex like the Node.js event loop, so once a worker picks up a task it runs to completion on that OS thread.

### Ruby (Puma) — `rb_ary_shift` uprobe

Puma has two paths for incoming requests. In the **direct path**, the worker thread reads HTTP data itself — `server_or_client_trace()` fires on the worker and sets `traces_ctx_v1` correctly with no extra work. In the **reactor path** (when all workers are busy), the reactor thread reads HTTP data (setting `traces_ctx_v1` for itself), then enqueues the connection for a worker thread that has no context.

OBI hooks `rb_ary_shift` (Ruby's `Array#shift`), which fires when a Puma worker picks up a task from the todo queue. The BPF handler:

1. Updates `puma_worker_tasks[worker_tid] = reactor_tid` (thread mapping).
2. Looks up `server_traces_aux` via `puma_task_connections` to find the reactor's server trace.
3. If found, calls `obi_ctx__set(worker_pid_tgid, &tp)`.

In the direct path, `server_traces_aux` won't have an entry yet (HTTP hasn't been parsed), so step 2 is a harmless no-op.

## Requirements

- `CAP_SYS_ADMIN` capability and permission to use `bpf_probe_write_user` (kernel security lockdown mode should be `[none]`)
- The target application writes logs in **JSON format**
- BPFFS mounted at `/sys/fs/bpf` (or another mountpath configurable via `config.ebpf.bpf_fs_path` / `OTEL_EBPF_BPF_FS_PATH`)
