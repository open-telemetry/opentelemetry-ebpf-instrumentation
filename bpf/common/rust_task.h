// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>
#include <common/event_defs.h>
#include <common/runtime.h>
#include <common/trace_key.h>
#include <logger/bpf_dbg.h>

#include <maps/rust_tasks.h>
#include <maps/server_traces.h>
#include <pid/pid.h>

/*
 * Tokio tasks can move between workers, and one worker can poll unrelated requests,
 * so an OS thread ID alone cannot identify the request that caused an operation.
 *
 * Poll probes maintain a stack of task addresses per worker. These helpers resolve
 * the innermost active task and use its address to retrieve request context.
 * `id` is bpf_get_current_pid_tgid(). Shared address keys include the PID so
 * identical virtual addresses in different processes remain independent.
 *
 */

static __always_inline bool rust_process_instrumented(u64 id) {
    const u32 pid = obi_pid(id);
    return bpf_map_lookup_elem(&rust_capabilities, &pid) != NULL;
}

// Returns the capabilities published for the process, keyed by its pid in OBI's namespace.
static __always_inline const rust_capabilities_t *rust_process_capabilities(u32 pid) {
    return bpf_map_lookup_elem(&rust_capabilities, &pid);
}

// Tracking tasks and proving client request handoffs are separate capabilities:
// missing handoff hooks must not disable otherwise usable task tracking.
// Reports whether task-based request context tracking is enabled for the process.
static __always_inline bool rust_task_context_enabled(u64 id) {
    const rust_capabilities_t *capabilities = rust_process_capabilities(obi_pid(id));

    return capabilities && capabilities->task_context;
}

// Returns the poll state of a thread that has polled a Tokio task, or NULL for a plain
// thread. A plain thread serves one request at a time, so its thread-keyed server span
// identifies the request, while a polling thread's may belong to any task it ran.
static __always_inline const rust_thread_state_t *rust_task_thread(u64 id) {
    const rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);

    return thread && thread->polled_task ? thread : NULL;
}

// Resolves the innermost task of a worker's poll stack into a PID-scoped key.
// Returns false when the worker is outside a task or its stack overflowed.
static __always_inline bool
rust_innermost_task(u32 pid, const rust_thread_state_t *thread, rust_task_key_t *key) {
    if (!thread->depth || thread->depth > k_rust_poll_depth) {
        return false;
    }

    u32 index = thread->depth - 1;
    if (index >= k_rust_poll_depth) {
        return false;
    }

    bpf_clamp_umax(index, k_rust_poll_depth - 1);
    *key = (rust_task_key_t){.pid = pid, .addr = thread->tasks[index]};

    return key->addr != 0;
}

// Resolves the innermost task on the current worker of a process whose pid and
// capabilities the caller already fetched. Returns false when task tracking is
// unavailable or the worker state is invalid.
static __always_inline bool
rust_process_task(u64 id, u32 pid, const rust_capabilities_t *capabilities, rust_task_key_t *key) {
    if (!capabilities || !capabilities->task_context) {
        return false;
    }

    const rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);

    return thread && rust_innermost_task(pid, thread, key);
}

// Resolves the innermost task on the current worker into a PID-scoped key.
// Returns false when task tracking is unavailable or the worker state is invalid.
static __always_inline bool rust_current_task(u64 id, rust_task_key_t *key) {
    const u32 pid = obi_pid(id);

    return rust_process_task(id, pid, rust_process_capabilities(pid), key);
}

// Looks up the request context of a worker's innermost task, from state the caller
// already fetched after checking that task tracking is enabled.
static __always_inline tp_info_pid_t *rust_thread_context(u64 id,
                                                          const rust_thread_state_t *thread) {
    rust_task_key_t key = {};

    return rust_innermost_task(obi_pid(id), thread, &key)
               ? bpf_map_lookup_elem(&rust_task_context, &key)
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

// Looks up the server request the current thread is serving, under the key server
// capture stores it with.
static __always_inline const tp_info_pid_t *rust_thread_server_trace(void) {
    trace_key_t t_key = {};
    task_tid(&t_key.p_key);
    t_key.extra_id = extra_runtime_id();

    return bpf_map_lookup_elem(&server_traces, &t_key);
}

// Returns the context work handed off by the current thread inherits: the polled
// task's context inside a task poll, or the request a plain thread is serving.
// A thread that has polled tasks has none between polls.
static __always_inline const tp_info_pid_t *rust_spawner_context(u64 id) {
    const rust_thread_state_t *thread = rust_task_thread(id);
    if (thread) {
        return rust_thread_context(id, thread);
    }

    return rust_thread_server_trace();
}

// Snapshots the spawner's context into a task or message map under key, for a
// caller that checked the process is instrumented.
// Without a parent the key is deleted instead: a missing entry already means no
// context, so a recycled key cannot retain an old parent, and context-less tasks
// do not fill the LRU slots that live request contexts need.
// The destination must store rust_task_key_t -> tp_info_pid_t.
static __always_inline void rust_copy_context(u64 id, void *map, const rust_task_key_t *key) {
    const tp_info_pid_t *parent = rust_spawner_context(id);
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
