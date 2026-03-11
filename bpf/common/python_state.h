// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <maps/python_context_task.h>
#include <maps/python_task_state.h>

static __always_inline u64 python_next_task_version(u64 task) {
    const python_task_state_t *task_state =
        (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &task);
    if (!task_state || !task_state->version) {
        return 1;
    }

    u64 version = task_state->version + 1;
    return version ? version : 1;
}

static __always_inline u64 resolve_python_context_task(const python_context_task_t *context_task,
                                                       const python_task_state_t **task_state) {
    if (task_state) {
        *task_state = NULL;
    }
    if (!context_task || !context_task->task) {
        return 0;
    }

    const python_task_state_t *state =
        (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &context_task->task);
    if (context_task->version && (!state || state->version != context_task->version)) {
        return 0;
    }
    if (task_state) {
        *task_state = state;
    }

    return context_task->task;
}
