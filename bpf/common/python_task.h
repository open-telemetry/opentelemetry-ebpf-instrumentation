// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <maps/python_context_task.h>
#include <maps/python_task_state.h>

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
