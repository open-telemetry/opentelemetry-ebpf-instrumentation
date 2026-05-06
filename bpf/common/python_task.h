// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>

#include <maps/python_context_task.h>
#include <maps/python_task_state.h>
#include <maps/server_traces.h>

static __always_inline u64 resolve_python_context_task(const python_context_task_t *context_task) {
    if (!context_task || !context_task->task) {
        return 0;
    }

    if (!context_task->version) {
        return context_task->task;
    }

    const python_task_state_t *task_state =
        (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &context_task->task);
    if (!task_state || task_state->version != context_task->version) {
        return 0;
    }

    return context_task->task;
}

// Walks the python_task_state parent chain looking for the server trace that
// owns task_id. Returns the raw server_traces_aux entry (caller filters on valid)
static __always_inline tp_info_pid_t *find_python_owning_server_trace(u64 task_id) {
    enum { k_max_depth = 4 };
    for (u8 i = 0; i < k_max_depth; ++i) {
        const python_task_state_t *task_state =
            (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &task_id);
        if (!task_state) {
            return NULL;
        }
        if (task_state->conn.port) {
            tp_info_pid_t *tp = bpf_map_lookup_elem(&server_traces_aux, &task_state->conn);
            if (tp) {
                return tp;
            }
        }
        if (!task_state->parent) {
            return NULL;
        }
        task_id = task_state->parent;
    }
    return NULL;
}
