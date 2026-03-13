// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/python_context_task.h>
#include <maps/python_task_state.h>
#include <maps/python_thread_state.h>

#include <common/connection_info.h>

#include <generictracer/maps/pid_tid_to_conn.h>

#include <pid/pid.h>

static __always_inline u64 python_next_task_version(u64 task) {
    const python_task_state_t *task_state =
        (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &task);
    if (!task_state || !task_state->version) {
        return 1;
    }

    u64 version = task_state->version + 1;
    return version ? version : 1;
}

static __always_inline void map_context_to_task(u64 context, u64 task) {
    python_context_task_t mapping = {
        .task = task,
        .version = 0,
    };

    const python_task_state_t *task_state =
        (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &task);
    if (task_state) {
        mapping.version = task_state->version;
    }

    bpf_map_update_elem(&python_context_task, &context, &mapping, BPF_ANY);
}

static __always_inline python_thread_state_t load_python_thread_state(u64 id) {
    const python_thread_state_t *thread_state_ptr =
        (const python_thread_state_t *)bpf_map_lookup_elem(&python_thread_state, &id);
    python_thread_state_t thread_state = {};
    if (thread_state_ptr) {
        thread_state = *thread_state_ptr;
    }

    return thread_state;
}

static __always_inline int update_current_task(u64 id, u64 task) {
    if (!task) {
        return 0;
    }

    bpf_dbg_printk("task_step: tid=%d task=%llx", id, task);
    python_thread_state_t thread_state = load_python_thread_state(id);
    thread_state.current_task = task;
    bpf_map_update_elem(&python_thread_state, &id, &thread_state, BPF_ANY);
    return 0;
}

SEC("uprobe/_asyncio.so:task_step_legacy")
int obi_uprobe_task_step_legacy(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    return update_current_task(id, (u64)PT_REGS_PARM1(ctx));
}

SEC("uprobe/_asyncio.so:task_step")
int obi_uprobe_task_step(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    return update_current_task(id, (u64)PT_REGS_PARM2(ctx));
}

SEC("uprobe/_asyncio.so:task_step_ret")
int obi_uprobe_task_step_ret(struct pt_regs *ctx) {
    (void)ctx;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("task_step_ret: clearing tid=%d", id);
    python_thread_state_t thread_state = load_python_thread_state(id);
    thread_state.current_task = 0;
    if (!thread_state.current_context && !thread_state.inflight_task) {
        bpf_map_delete_elem(&python_thread_state, &id);
        return 0;
    }

    bpf_map_update_elem(&python_thread_state, &id, &thread_state, BPF_ANY);
    return 0;
}

SEC("uprobe/libpython3.:context_run")
int obi_uprobe_context_run(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }

    u64 context = (u64)PT_REGS_PARM1(ctx);
    if (!context) {
        return 0;
    }
    bpf_dbg_printk("context_run: tid=%d ctx=%llx", id, context);

    // Read the full thread snapshot once so this probe can update the active
    // context without dropping the task-init state stored on the same thread.
    python_thread_state_t thread_state = load_python_thread_state(id);
    thread_state.current_context = context;
    bpf_map_update_elem(&python_thread_state, &id, &thread_state, BPF_ANY);

    return 0;
}

// PyContext_CopyCurrent is called in two key places:
//   1. Inside _asyncio_Task___init___impl when context=Py_None (task creation)
//   2. In asyncio.to_thread via contextvars.copy_context() (thread dispatch)
SEC("uprobe/libpython3.:PyContext_CopyCurrent")
int obi_uprobe_copy_context(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u64 context = (u64)PT_REGS_RC(ctx);
    if (!context) {
        return 0;
    }

    // Task initialization copies the new context before the child task shows up
    // in task_step, so the inflight child is the only safe owner here.
    const python_thread_state_t *thread_state =
        (const python_thread_state_t *)bpf_map_lookup_elem(&python_thread_state, &id);
    if (thread_state && thread_state->inflight_task) {
        map_context_to_task(context, thread_state->inflight_task);
        bpf_dbg_printk("copy_context: mapped context=%llx child_task=%llx",
                       context,
                       thread_state->inflight_task);
        return 0;
    }

    // On the event-loop thread, copy_context still runs inside the task that is
    // serving the request, so bind the new context directly to that task.
    if (thread_state && thread_state->current_task) {
        map_context_to_task(context, thread_state->current_task);
        bpf_dbg_printk(
            "copy_context: mapped context=%llx task=%llx", context, thread_state->current_task);
        return 0;
    }
    return 0;
}

SEC("uprobe/_asyncio.so:_asyncio_Task___init__")
int obi_uprobe_task_init(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u64 child_task = (u64)PT_REGS_PARM1(ctx);
    if (!child_task) {
        return 0;
    }

    // Store child_task so copy_context can attribute the copied context before
    // task_step starts running on the new task.
    python_thread_state_t thread_state = load_python_thread_state(id);
    thread_state.inflight_task = child_task;
    bpf_map_update_elem(&python_thread_state, &id, &thread_state, BPF_ANY);
    u64 parent_task = thread_state.current_task;
    python_task_state_t task_state = {
        .parent = parent_task,
        .version = python_next_task_version(child_task),
    };

    bpf_dbg_printk(
        "task_init: parent_lookup tid=%d child=%llx parent=%llx", id, child_task, parent_task);

    const python_task_state_t *parent_state = NULL;
    if (parent_task) {
        parent_state =
            (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &parent_task);
    }

    // Use the parent's connection when it exists. If there is no parent
    // connection yet, fall back to pid_tid_to_conn for the current thread.
    // pid_tid_to_conn is only thread-local and may already point to another
    // request by the time the child task is initialized.
    if (parent_state && parent_state->conn.port) {
        task_state.conn = parent_state->conn;
        bpf_dbg_printk("task_init: stored state (from parent) for task=%llx parent=%llx port=%d",
                       child_task,
                       parent_task,
                       task_state.conn.port);
    } else {
        ssl_pid_connection_info_t *info = bpf_map_lookup_elem(&pid_tid_to_conn, &id);
        if (info) {
            connection_info_part_t conn_part = {};
            u32 host_pid = pid_from_pid_tgid(id);
            populate_ephemeral_info(
                &conn_part, &info->p_conn.conn, info->orig_dport, host_pid, FD_SERVER);
            task_state.conn = conn_part;
            bpf_dbg_printk(
                "task_init: stored state for task=%llx port=%d", child_task, conn_part.port);
        }
    }
    bpf_map_update_elem(&python_task_state, &child_task, &task_state, BPF_ANY);

    return 0;
}

SEC("uprobe/_asyncio.so:_asyncio_Task___init___ret")
int obi_uprobe_task_init_ret(struct pt_regs *ctx) {
    (void)ctx;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    python_thread_state_t thread_state = load_python_thread_state(id);
    thread_state.inflight_task = 0;
    if (!thread_state.current_task && !thread_state.current_context) {
        bpf_map_delete_elem(&python_thread_state, &id);
        return 0;
    }

    bpf_map_update_elem(&python_thread_state, &id, &thread_state, BPF_ANY);
    return 0;
}
