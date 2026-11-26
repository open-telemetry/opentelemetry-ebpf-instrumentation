// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_tracing.h>

#include <common/rust_task.h>
#include <common/preempt_guard.h>
#include <pid/pid.h>
#include <shared/obi_ctx.h>

// Returns the worker's poll state, creating it the first time the worker runs a task.
static __always_inline rust_thread_state_t *rust_thread_state(u64 id) {
    rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);
    if (thread) {
        return thread;
    }

    const rust_thread_state_t initial = {};
    bpf_map_update_elem(&rust_threads, &id, &initial, BPF_ANY);
    thread = bpf_map_lookup_elem(&rust_threads, &id);
    if (!thread) {
        bpf_dbg_printk("rust thread state unavailable");
    }

    return thread;
}

static __always_inline void rust_publish_thread_context(u64 id, const tp_info_pid_t *context) {
    if (context && context->valid) {
        obi_ctx__set(id, &context->tp);
    } else {
        obi_ctx__del(id);
    }
}

static __always_inline void rust_refresh_thread_context(u64 id) {
    rust_publish_thread_context(id, rust_current_context(id));
}

// Enter a task while Tokio polls it, through either raw::poll or Harness::poll.
// The worker's task stack selects its parent context even across nested polls.
SEC("uprobe/rust:tokio_poll")
int GUARDED_PROG(obi_rust_task_poll, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!rust_task_context_enabled(id) || !valid_pid(id)) {
        return 0;
    }

    rust_thread_state_t *thread = rust_thread_state(id);
    if (!thread) {
        return 0;
    }

    thread->polled_task = 1;
    u32 depth = thread->depth;
    if (depth < k_rust_poll_depth) {
        bpf_clamp_umax(depth, k_rust_poll_depth - 1);
        thread->tasks[depth] = PT_REGS_PARM1(ctx);
    } else {
        bpf_dbg_printk("rust poll depth exceeded depth=%u", depth);
    }

    thread->depth++;
    bpf_dbg_printk("rust poll task=%llx, depth=%u, ip=%llx",
                   PT_REGS_PARM1(ctx),
                   thread->depth,
                   PT_REGS_IP(ctx));
    // Task tracking was checked and the worker state fetched above: reuse both per poll.
    rust_publish_thread_context(id, rust_thread_context(id, thread));

    return 0;
}

// Leave the polled task and restore the enclosing task's context. At the outermost
// return, clear the worker spawn state before another task runs.
SEC("uretprobe/rust:tokio_poll")
int GUARDED_PROG(obi_rust_task_poll_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);
    if (!thread || !rust_task_context_enabled(id)) {
        return 0;
    }

    if (thread->depth) {
        thread->depth--;
        bpf_dbg_printk("rust poll return depth=%u", thread->depth);
    } else {
        bpf_dbg_printk("rust poll return without matching entry");
    }

    if (!thread->depth) {
        thread->spawn_depth = 0;
    }

    rust_publish_thread_context(id, rust_thread_context(id, thread));
    return 0;
}

static __always_inline void rust_new_task(u64 id, u64 address) {
    const rust_task_key_t key = {.pid = obi_pid(id), .addr = address};
    if (!key.addr || !rust_task_context_enabled(id) || !valid_pid(id)) {
        return;
    }

    bpf_dbg_printk("rust task create task=%llx", key.addr);
    rust_inherit_task_context(id, &key);
}

// Snapshot the spawning task's parent when Cell::new or RawTask::new returns its
// allocation, before Tokio can publish the new task to another worker.
SEC("uretprobe/rust:tokio_new")
int GUARDED_PROG(obi_rust_task_new, struct pt_regs *, ctx) {
    rust_new_task(bpf_get_current_pid_tgid(), PT_REGS_RC(ctx));
    return 0;
}

// Copy the parent at owned-task binding or scheduler publication. These boundaries
// cover builds that inline task allocation, before the task can run elsewhere.
SEC("uprobe/rust:tokio_bind")
int GUARDED_PROG(obi_rust_task_bind, struct pt_regs *, ctx) {
    rust_new_task(bpf_get_current_pid_tgid(), PT_REGS_PARM2(ctx));
    return 0;
}

// Marks a spawn scope for the schedule fallback. Only tasks scheduled inside this
// scope inherit the caller's context, later wakes must keep their original parent.
SEC("uprobe/rust:tokio_spawn")
int GUARDED_PROG(obi_rust_task_spawn, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    if (!rust_task_context_enabled(id) || !valid_pid(id)) {
        return 0;
    }

    rust_thread_state_t *thread = rust_thread_state(id);
    if (thread) {
        thread->spawn_depth++;
        bpf_dbg_printk("rust spawn enter depth=%u", thread->spawn_depth);
    }
    return 0;
}

// Ends the spawn scope so unrelated task wakes on this worker cannot overwrite
// their saved parent with the context of the task that happens to wake them.
SEC("uretprobe/rust:tokio_spawn")
int GUARDED_PROG(obi_rust_task_spawn_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);

    if (thread && rust_task_context_enabled(id) && thread->spawn_depth) {
        thread->spawn_depth--;
        bpf_dbg_printk("rust spawn return depth=%u", thread->spawn_depth);
    }

    return 0;
}

static __always_inline void rust_schedule_task(u64 id, u64 task) {
    const rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);

    // Publish the parent before scheduling when allocation/binding was inlined.
    // Wakes outside a spawn scope must preserve the task's existing parent.
    if (thread && rust_task_context_enabled(id) && thread->spawn_depth) {
        bpf_dbg_printk("rust spawn publish task=%llx", task);
        rust_new_task(id, task);
    }
}

// Inherits the parent at scheduling when allocation and binding were inlined.
// The spawn scope distinguishes a new task's publication from later wakes.
SEC("uprobe/rust:tokio_schedule")
int GUARDED_PROG(obi_rust_task_schedule, struct pt_regs *, ctx) {
    rust_schedule_task(bpf_get_current_pid_tgid(), PT_REGS_PARM2(ctx));
    return 0;
}

// Initial multi-thread submissions bypass Schedule::schedule. Here the core is
// the second argument and the allocated Notified task is the third, before enqueue.
SEC("uprobe/rust:tokio_schedule_local")
int GUARDED_PROG(obi_rust_task_schedule_local, struct pt_regs *, ctx) {
    rust_schedule_task(bpf_get_current_pid_tgid(), PT_REGS_PARM3(ctx));
    return 0;
}

// Drops context before Tokio reuses the task allocation.
SEC("uprobe/rust:tokio_dealloc")
int GUARDED_PROG(obi_rust_task_dealloc, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_task_key_t key = {
        .pid = obi_pid(id),
        .addr = PT_REGS_PARM1(ctx),
    };

    if (rust_process_instrumented(id)) {
        bpf_dbg_printk("rust task dealloc task=%llx", key.addr);
        bpf_map_delete_elem(&rust_task_context, &key);
    }

    return 0;
}
