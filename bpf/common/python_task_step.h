// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/python_task.h>

#include <maps/python_thread_state.h>

#include <shared/obi_ctx.h>

// Python task/context pointers use 0 to mean "no active state" in thread-local tracking.
enum { k_python_state_none = 0 };

static __always_inline void refresh_obi_ctx_for_task(u64 pid_tgid,
                                                     const python_task_ref_t *task_ref) {
    if (!task_ref || !task_ref->addr) {
        obi_ctx__del(pid_tgid);
        return;
    }
    python_task_resolution_t resolution = PYTHON_TASK_NOT_FOUND;
    tp_info_pid_t *tp = find_python_owning_server_trace(pid_tgid, *task_ref, &resolution);
    if (tp && tp->valid) {
        obi_ctx__set(pid_tgid, &tp->tp);
        return;
    }
    obi_ctx__del(pid_tgid);
}

static __always_inline void
python_set_current_task(u64 pid_tgid, python_thread_state_t *thread_state, u64 task) {
    thread_state->current_task = task;
    python_task_ref_t task_ref = {};
    if (task != k_python_state_none) {
        resolve_python_task_ref(pid_tgid, task, &task_ref);
    }
    refresh_obi_ctx_for_task(pid_tgid, &task_ref);
}

// A task step starts on this thread (task_step / task_step_impl entry).
//
// A step can start while another task's step is still running: on Python 3.12+ an eager task
// (e.g. asyncio.eager_task_factory) runs its first step inside the parent's step that created it.
// The enclosing task is kept so its context comes back when the nested step returns. A step of
// the task that is already current (task_step calling task_step_impl) is not a new level.
static __always_inline void
python_task_step_enter(u64 pid_tgid, python_thread_state_t *thread_state, u64 task) {
    const u64 outer = thread_state->current_task;
    if (outer == k_python_state_none) {
        // A step started from the event loop: no step of this thread can still be running, so
        // anything left from missed returns is stale.
        thread_state->outer_depth = 0;
        thread_state->outer_overflow = 0;
    } else if (outer != task) {
        const u8 depth = thread_state->outer_depth;
        if (depth < k_python_outer_tasks_max) {
            thread_state->outer_tasks[depth & (k_python_outer_tasks_max - 1)] = outer;
            thread_state->outer_depth = depth + 1;
        } else if (thread_state->outer_overflow < 0xff) {
            // Too deep to store: counted so the stored levels still unwind in order.
            thread_state->outer_overflow++;
        }
    }
    python_set_current_task(pid_tgid, thread_state, task);
}

// A task step returns on this thread (task_step / task_step_impl return).
static __always_inline void python_task_step_exit(u64 pid_tgid,
                                                  python_thread_state_t *thread_state) {
    thread_state->start_monotime_ns = bpf_ktime_get_ns();

    if (thread_state->outer_overflow) {
        // A step too deep to store returns: its enclosing task is unknown.
        thread_state->outer_overflow--;
        python_set_current_task(pid_tgid, thread_state, k_python_state_none);
        return;
    }

    const u8 depth = thread_state->outer_depth;
    if (depth > 0 && depth <= k_python_outer_tasks_max) {
        // A nested step returns: the enclosing task is running again.
        const u64 outer = thread_state->outer_tasks[(depth - 1) & (k_python_outer_tasks_max - 1)];
        thread_state->outer_tasks[(depth - 1) & (k_python_outer_tasks_max - 1)] =
            k_python_state_none;
        thread_state->outer_depth = depth - 1;
        python_set_current_task(pid_tgid, thread_state, outer);
        return;
    }

    // Back to the event loop: idle loop code belongs to no task.
    python_set_current_task(pid_tgid, thread_state, k_python_state_none);
}
