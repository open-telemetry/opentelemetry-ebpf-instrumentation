// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>
#include <common/event_defs.h>
#include <common/scratch_mem.h>
#include <logger/bpf_dbg.h>

#include <maps/rust_tasks.h>
#include <maps/rust_protocol.h>
#include <pid/pid.h>

/*
 * Context bridge functions between Rust runtime uprobes, generic protocol capture, and the tpinjector.
 * Tokio tasks can move between workers, and one worker can poll unrelated requests,
 * so an OS thread ID alone cannot identify the request that caused an operation.
 *
 * Poll probes maintain a stack of task addresses per worker. These helpers resolve
 * the innermost active task and use its address to retrieve request context.
 * `id` is bpf_get_current_pid_tgid(). Shared address keys include the PID so
 * identical virtual addresses in different processes remain independent.
 *
 * Server capture installs a task context. Spawn and Hyper queue probes snapshot this context
 * before an async handoff, while receivers restore it on the task handling that work.
 * Missing snapshots clear the driver's old parent instead of borrowing another request's.
 * Client ownership and wire-parent records connect that context to socket injection
 * and to the client span subsequently created by generic capture.
 */

SCRATCH_MEM_TYPED(rust_io_connection, ssl_pid_connection_info_t)
SCRATCH_MEM_TYPED(rust_wire_key, rust_wire_key_t)

static __always_inline bool rust_process_instrumented(u64 id) {
    const u32 pid = obi_pid(id);
    return bpf_map_lookup_elem(&rust_capabilities, &pid) != NULL;
}

// Tracking tasks and proving client request handoffs are separate capabilities:
// missing handoff hooks must not disable otherwise usable task tracking.
// Reports whether task-based request context tracking is enabled for the process.
static __always_inline bool rust_task_context_enabled(u64 id) {
    const u32 pid = obi_pid(id);
    const rust_capabilities_t *capabilities = bpf_map_lookup_elem(&rust_capabilities, &pid);

    return capabilities && capabilities->task_context;
}

// Reports whether Rust client request handoff tracking is enabled for the process.
static __always_inline bool rust_client_context_enabled(u64 id) {
    const u32 pid = obi_pid(id);
    const rust_capabilities_t *capabilities = bpf_map_lookup_elem(&rust_capabilities, &pid);

    return capabilities && capabilities->client_context;
}

// Reports whether the process contains a Tokio runtime. Its workers poll unrelated
// tasks even when the task tracking hooks are unavailable.
static __always_inline bool rust_tokio_runtime(u64 id) {
    const u32 pid = obi_pid(id);
    const rust_capabilities_t *capabilities = bpf_map_lookup_elem(&rust_capabilities, &pid);

    return capabilities && capabilities->tokio_runtime;
}

// Resolves the innermost task of a worker's poll stack into a PID-scoped key.
// Returns false when the worker is outside a task or its stack overflowed.
static __always_inline bool
rust_innermost_task(u64 id, const rust_thread_state_t *thread, rust_task_key_t *key) {
    if (!thread->depth || thread->depth > k_rust_poll_depth) {
        return false;
    }

    u32 index = thread->depth - 1;
    if (index >= k_rust_poll_depth) {
        return false;
    }

    bpf_clamp_umax(index, k_rust_poll_depth - 1);
    *key = (rust_task_key_t){.pid = obi_pid(id), .addr = thread->tasks[index]};

    return key->addr != 0;
}

// Resolves the innermost task on the current worker into a PID-scoped key.
// Returns false when task tracking is unavailable or the worker state is invalid.
static __always_inline bool rust_current_task(u64 id, rust_task_key_t *key) {
    if (!rust_task_context_enabled(id)) {
        return false;
    }

    const rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);

    return thread && rust_innermost_task(id, thread, key);
}

// Looks up the request context of a worker's innermost task, from state the caller
// already fetched after checking that task tracking is enabled.
static __always_inline tp_info_pid_t *rust_thread_context(u64 id,
                                                          const rust_thread_state_t *thread) {
    rust_task_key_t key = {};

    return rust_innermost_task(id, thread, &key) ? bpf_map_lookup_elem(&rust_task_context, &key)
                                                 : NULL;
}

// Looks up the request context associated with the current Rust task.
static __always_inline tp_info_pid_t *rust_current_context(u64 id) {
    rust_task_key_t key = {};
    if (!rust_current_task(id, &key)) {
        return NULL;
    }

    return bpf_map_lookup_elem(&rust_task_context, &key);
}

// Stores or replaces the request context for the current Rust task.
static __always_inline void rust_set_context(u64 id, const tp_info_pid_t *context) {
    rust_task_key_t key = {};

    if (rust_current_task(id, &key)) {
        const long result = bpf_map_update_elem(&rust_task_context, &key, context, BPF_ANY);
        if (result) {
            bpf_dbg_printk("rust context store failed task=%llx err=%ld", key.addr, result);
        } else {
            bpf_dbg_printk("rust context task=%llx valid=%u", key.addr, context->valid);
        }
    }
}

// Snapshots the current task's context into a task or message map under key.
// Without a parent the key is deleted instead: a missing entry already means no
// context, so a recycled key cannot retain an old parent, and context-less tasks
// do not fill the LRU slots that live request contexts need.
// The destination must store rust_task_key_t -> tp_info_pid_t.
static __always_inline void rust_copy_context(u64 id, void *map, const rust_task_key_t *key) {
    const tp_info_pid_t *parent = rust_current_context(id);
    if (!parent || !parent->valid) {
        bpf_map_delete_elem(map, key);
        bpf_dbg_printk("rust inherit none key=%llx pid=%u", key->addr, key->pid);
        return;
    }

    const tp_info_pid_t context = *parent;
    const long result = bpf_map_update_elem(map, key, &context, BPF_ANY);
    if (result) {
        bpf_dbg_printk("rust inherit failed key=%llx err=%ld", key->addr, result);
    } else {
        bpf_dbg_printk("rust inherit key=%llx pid=%u valid=%u", key->addr, key->pid, context.valid);
    }
}

// A spawned task can outlive the request that spawned it, such as a database
// connection driver started by its first caller and reused by later requests.
// Its inherited parent is therefore marked as possibly ended: parent_kind() then
// makes the link conditional, and userspace keeps it only for client calls that
// start before that request ends.
static __always_inline void rust_inherit_task_context(u64 id, const rust_task_key_t *key) {
    rust_copy_context(id, &rust_task_context, key);

    // The task is not published to any worker yet, so nothing reads this copy concurrently.
    tp_info_pid_t *inherited = bpf_map_lookup_elem(&rust_task_context, key);
    if (inherited && inherited->valid) {
        inherited->response_sent = 1;
    }
}

// Restores a queued channel context onto the receiving task and consumes the queue entry.
// A missing entry clears the receiver's previous context.
static __always_inline void rust_adopt_channel_context(u64 id, const rust_task_key_t *key) {
    tp_info_pid_t context = {};
    const tp_info_pid_t *queued = bpf_map_lookup_elem(&rust_channel_context, key);

    if (queued) {
        context = *queued;
        bpf_dbg_printk("rust handoff key=%llx valid=%u", key->addr, context.valid);
    } else {
        bpf_dbg_printk("rust handoff missing key=%llx pid=%u", key->addr, key->pid);
    }

    rust_set_context(id, &context);
    bpf_map_delete_elem(&rust_channel_context, key);
}

// Returns the process's validated ABI offsets and independently enabled protocol capabilities.
static __always_inline const rust_protocol_config_t *rust_protocol_config(u64 id) {
    const u32 pid = obi_pid(id);
    return bpf_map_lookup_elem(&rust_protocol_configs, &pid);
}

// Saves the original parent under the outgoing trace/span IDs and PID.
// Header creation can precede generic span creation, so the parent must survive later task changes.
static __always_inline void
rust_save_wire_parent(u64 id, const tp_info_t *wire, const tp_info_pid_t *parent) {
    rust_wire_key_t key = {.pid = obi_pid(id)};
    __builtin_memcpy(key.trace_id, wire->trace_id, sizeof(key.trace_id));
    __builtin_memcpy(key.span_id, wire->span_id, sizeof(key.span_id));

    const long result = bpf_map_update_elem(&rust_wire_parents, &key, parent, BPF_ANY);
    if (result) {
        bpf_dbg_printk("rust wire parent store failed pid=%u err=%ld", key.pid, result);
    }
}

// Looks up the saved parent matching the outgoing trace/span IDs and PID.
static __always_inline tp_info_pid_t *rust_wire_parent(u64 id, const tp_info_t *wire) {
    if (!wire) {
        return NULL;
    }

    rust_wire_key_t *key = rust_wire_key_mem();
    if (!key) {
        return NULL;
    }

    key->pid = obi_pid(id);
    __builtin_memcpy(key->trace_id, wire->trace_id, sizeof(key->trace_id));
    __builtin_memcpy(key->span_id, wire->span_id, sizeof(key->span_id));

    return bpf_map_lookup_elem(&rust_wire_parents, key);
}

// Associates the current task with a socket and original destination port.
// Decoded HTTP/2 server requests use this identity to look up their stream's parent.
static __always_inline void
rust_save_io_connection(u64 id, const pid_connection_info_t *conn, u16 orig_dport) {
    rust_task_key_t key = {};

    if (rust_current_task(id, &key)) {
        ssl_pid_connection_info_t *info = rust_io_connection_mem();
        if (info) {
            __builtin_memset(info, 0, sizeof(*info));
            info->p_conn = *conn;
            info->orig_dport = orig_dport;
            bpf_map_update_elem(&rust_io_connections, &key, info, BPF_ANY);
        }
    }
}

// Reports whether the current task has a saved socket. The decoded HTTP/2 request
// hook needs both the task and its socket to find the stream it adopts a parent for.
static __always_inline bool rust_task_has_io_connection(u64 id) {
    rust_task_key_t key = {};

    return rust_current_task(id, &key) && bpf_map_lookup_elem(&rust_io_connections, &key);
}

// Returns the current task's pending HTTP/1 request unless generic capture already observed it.
// Each connection task has one pending request for socket injection; observed requests lose ownership.
static __always_inline rust_http_request_t *rust_current_request(u64 id) {
    rust_task_key_t task = {};
    rust_http_request_t *request =
        rust_current_task(id, &task) ? bpf_map_lookup_elem(&rust_http1_requests, &task) : NULL;
    return request && !request->observed ? request : NULL;
}

static __always_inline bool rust_request_has_wire_context(const rust_http_request_t *request) {
    if (!request) {
        return false;
    }
    if (request->injection_result == k_rust_injection_succeeded) {
        return true;
    }
    return request->injection_result == k_rust_injection_application_owned && !request->forwarded;
}

static __always_inline void
rust_socket_trace(const rust_http_request_t *request, u32 pid, tp_info_pid_t *trace) {
    __builtin_memset(trace, 0, sizeof(*trace));
    trace->tp = request->wire;
    trace->pid = pid;
    trace->valid = 1;
    trace->req_type = k_event_type_http_client;
}

// Marks the current HTTP/1 request as observed so later writes cannot reuse its ownership.
static __always_inline void rust_observe_request(u64 id) {
    rust_http_request_t *request = rust_current_request(id);
    if (request) {
        request->observed = 1;
    }
}

// Saves or replaces the pending HTTP/1 request for the current task.
static __always_inline void rust_save_request(u64 id, const rust_http_request_t *request) {
    rust_task_key_t task = {};
    if (rust_current_task(id, &task)) {
        bpf_map_update_elem(&rust_http1_requests, &task, request, BPF_ANY);
    }
}

// Returns the unobserved HTTP/2 request for the current task's sender and stream ID.
// Resolving the sender first keeps ownership separate when stream IDs repeat across connections.
static __always_inline rust_http_request_t *rust_current_h2_request(u64 id, u32 stream_id) {
    rust_task_key_t task = {};
    if (!rust_current_task(id, &task)) {
        return NULL;
    }

    const u64 *sender = bpf_map_lookup_elem(&rust_h2_tasks, &task);
    if (!sender) {
        return NULL;
    }

    const rust_h2_key_t key = {.pid = task.pid, .sender = *sender, .stream_id = stream_id};

    rust_http_request_t *request = bpf_map_lookup_elem(&rust_h2_requests, &key);
    return request && !request->observed ? request : NULL;
}

// Records a socket connection under the end address of a Rustls deframer read range.
// Matching buffer ends establish the socket association before the Rustls connection is bound.
static __always_inline void
rust_save_read_range(u64 id, u64 address, u32 len, const pid_connection_info_t *conn, u16 port) {
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (!address || !len || !config || !config->rustls || !rust_process_instrumented(id)) {
        return;
    }

    const rust_task_key_t key = {.pid = obi_pid(id), .addr = address + len};
    ssl_pid_connection_info_t *info = rust_io_connection_mem();
    if (!info || key.addr < address) {
        return;
    }

    __builtin_memset(info, 0, sizeof(*info));
    info->p_conn = *conn;
    info->orig_dport = port;

    const long result = bpf_map_update_elem(&rust_tls_reads, &key, info, BPF_ANY);
    if (result) {
        bpf_dbg_printk("rust TLS read range failed end=%llx err=%ld", key.addr, result);
    } else {
        bpf_dbg_printk("rust TLS read range end=%llx len=%u port=%u", key.addr, len, port);
    }
}
