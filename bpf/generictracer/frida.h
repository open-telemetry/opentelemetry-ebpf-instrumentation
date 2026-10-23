// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/globals.h>
#include <common/pin_internal.h>
#include <common/map_sizing.h>
#include <common/trace_parent.h>
#include <common/tracing.h>

enum { k_frida_ioctl = 0x0b10f1 };

typedef struct frida_buffer_key {
    u32 pid;
    u32 padding;
    u64 buffer;
} frida_buffer_key_t;

typedef struct frida_context {
    tp_info_pid_t tp;
    u64 process_start;
    u8 parent_status;
    u8 padding[7];
} frida_context_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, frida_buffer_key_t);
    __type(value, frida_context_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} frida_contexts SEC(".maps");

typedef struct frida_request {
    u64 buffer;
    connection_info_t conn;
    unsigned char traceparent[TP_MAX_VAL_LENGTH];
    u8 ready;
    u8 padding[4];
} frida_request_t;

_Static_assert(sizeof(frida_request_t) == 104, "Frida context ABI size");
_Static_assert(__builtin_offsetof(frida_request_t, ready) == 99, "Frida context ABI ready offset");

static __always_inline int frida_context_request(const u64 id, void *arg) {
    if (!g_frida_enabled || !arg) {
        return 0;
    }
    frida_request_t request = {};
    if (bpf_probe_read_user(&request, sizeof(request), arg) != 0 || !request.buffer) {
        return 0;
    }

    frida_buffer_key_t key = {.pid = pid_from_pid_tgid(id), .buffer = request.buffer};
    if (request.ready == 2) {
        bpf_map_delete_elem(&frida_contexts, &key);
        return 0;
    }

    frida_context_t context = {};
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    context.process_start = BPF_CORE_READ(task, group_leader, start_time);
    context.tp.pid = pid_from_pid_tgid(id);
    context.tp.valid = 1;
    context.tp.req_type = k_event_type_http_client;
    context.tp.tp.ts = bpf_ktime_get_ns();
    context.tp.tp.flags = 1;
    urand_bytes(context.tp.tp.span_id, sizeof(context.tp.tp.span_id));
    pid_connection_info_t connection = {.conn = request.conn, .pid = context.tp.pid};
    sort_connection_info(&connection.conn);
    context.parent_status = find_trace_for_client_request(
        &connection, request.conn.d_port, k_lw_thread_none, &context.tp.tp);
    if (!context.parent_status) {
        new_trace_id(&context.tp.tp);
    }

    if (bpf_map_update_elem(&frida_contexts, &key, &context, BPF_ANY) != 0) {
        return 0;
    }

    make_tp_string(request.traceparent, &context.tp.tp);
    request.ready = 1;
    if (bpf_probe_write_user(arg, &request, sizeof(request)) != 0) {
        bpf_map_delete_elem(&frida_contexts, &key);
    }
    return 0;
}
