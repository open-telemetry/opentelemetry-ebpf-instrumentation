// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>

#include <maps/python_context_task.h>
#include <maps/python_task_state.h>
#include <maps/server_traces.h>

#include <pid/pid_helpers.h>

// ctx_vars offset in struct _pycontextobject: PyObject_HEAD + ctx_prev.
// Layout is identical across CPython 3.9-3.14 standard 64-bit builds.
// See https://github.com/python/cpython/blob/3.14/Include/internal/pycore_context.h#L21-L27
enum { k_python_context_vars_offset = 16 + 8 };

static __always_inline u64 read_python_context_vars(u64 context) {
    u64 vars = 0;
    bpf_probe_read_user(
        &vars, sizeof(vars), (const void *)(context + k_python_context_vars_offset));
    return vars;
}

static __always_inline python_addr_key_t python_addr_key(u64 pid_tgid, u64 addr) {
    python_addr_key_t key = {
        .pid = pid_from_pid_tgid(pid_tgid),
        .addr = addr,
    };
    return key;
}

static __always_inline u8 resolve_python_task_ref(u64 pid_tgid,
                                                  u64 task,
                                                  python_task_ref_t *task_ref) {
    if (!task || !task_ref) {
        return 0;
    }

    const python_addr_key_t task_key = python_addr_key(pid_tgid, task);
    const python_task_state_t *task_state =
        (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &task_key);
    if (!task_state || !task_state->generation) {
        return 0;
    }

    task_ref->addr = task;
    task_ref->generation = task_state->generation;
    return 1;
}

static __always_inline const python_task_state_t *
lookup_python_task_state(u64 pid_tgid, const python_task_ref_t *task_ref) {
    if (!task_ref || !task_ref->addr || !task_ref->generation) {
        return NULL;
    }

    const python_addr_key_t task_key = python_addr_key(pid_tgid, task_ref->addr);
    const python_task_state_t *task_state =
        (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &task_key);
    if (!task_state || task_state->generation != task_ref->generation) {
        return NULL;
    }

    return task_state;
}

static __always_inline u64 allocate_python_task_generation(void) {
    const u32 key = 0;
    u64 *counter = (u64 *)bpf_map_lookup_elem(&python_task_generation, &key);
    if (!counter) {
        return 0;
    }

    return __sync_fetch_and_add(counter, 1) + 1;
}

typedef enum python_task_resolution {
    PYTHON_TASK_NOT_FOUND = 0,
    PYTHON_TASK_RESOLVED,
    PYTHON_TASK_STALE,
} python_task_resolution_t;

static __always_inline u8 resolve_python_context_task(u64 pid_tgid,
                                                      const python_context_task_t *context_task,
                                                      python_task_ref_t *task_ref) {
    if (!context_task || !context_task->task.addr) {
        return 0;
    }

    if (!lookup_python_task_state(pid_tgid, &context_task->task)) {
        return 0;
    }

    if (task_ref) {
        *task_ref = context_task->task;
    }
    return 1;
}

// Resolve a context owner and tell callers whether another parent lookup is safe.
// Callers may continue fallback only when no context binding was found.
static __always_inline python_task_resolution_t
resolve_python_task_from_context(u64 pid_tgid, u64 context, python_task_ref_t *task_ref) {
    if (!context) {
        return PYTHON_TASK_NOT_FOUND;
    }

    const python_addr_key_t context_key = python_addr_key(pid_tgid, context);
    const python_context_task_t *context_task =
        (const python_context_task_t *)bpf_map_lookup_elem(&python_context_task, &context_key);
    if (!context_task) {
        return PYTHON_TASK_NOT_FOUND;
    }

    if (context_task->vars != read_python_context_vars(context)) {
        return PYTHON_TASK_STALE;
    }

    if (!resolve_python_context_task(pid_tgid, context_task, task_ref)) {
        return PYTHON_TASK_STALE;
    }

    return PYTHON_TASK_RESOLVED;
}

// Walk the task parent chain, validating each task instance before using its state.
static __always_inline tp_info_pid_t *find_python_owning_server_trace(
    u64 pid_tgid, python_task_ref_t task_ref, python_task_resolution_t *resolution) {
    if (resolution) {
        *resolution = PYTHON_TASK_NOT_FOUND;
    }

    enum { k_max_depth = 4 };
    for (u8 i = 0; i < k_max_depth; ++i) {
        const python_task_state_t *task_state = lookup_python_task_state(pid_tgid, &task_ref);
        if (!task_state) {
            if (resolution) {
                *resolution = PYTHON_TASK_STALE;
            }
            return NULL;
        }
        if (task_state->conn.port) {
            tp_info_pid_t *tp = bpf_map_lookup_elem(&server_traces_aux, &task_state->conn);
            if (tp) {
                if (resolution) {
                    *resolution = PYTHON_TASK_RESOLVED;
                }
                return tp;
            }
        }
        if (!task_state->parent.addr) {
            return NULL;
        }
        task_ref = task_state->parent;
    }
    return NULL;
}
