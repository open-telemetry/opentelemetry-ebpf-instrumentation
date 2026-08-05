// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_info.h>
#include <common/trace_key.h>

#include <logger/bpf_dbg.h>

#include <maps/server_traces.h>

// Returns the thread trace only if it still belongs to this request.
static __always_inline tp_info_pid_t *http_server_thread_trace(http_info_t *info,
                                                               trace_key_t *t_key) {
    t_key->extra_id = info->extra_id;
    t_key->p_key.ns = info->pid.ns;
    t_key->p_key.tid = info->task_tid;
    t_key->p_key.pid = info->pid.user_pid;

    tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, t_key);
    if (!existing) {
        return NULL;
    }

    if (bpf_memcmp(existing->tp.trace_id, info->tp.trace_id, TRACE_ID_SIZE_BYTES) != 0 ||
        bpf_memcmp(existing->tp.span_id, info->tp.span_id, SPAN_ID_SIZE_BYTES) != 0) {
        bpf_dbg_printk("server thread trace for tid=%d replaced by a newer request",
                       t_key->p_key.tid);
        return NULL;
    }

    return existing;
}

static __always_inline void
cleanup_http_server_thread_trace_for_key(http_info_t *info, const trace_key_t *current_key) {
    trace_key_t t_key = {0};
    if (!http_server_thread_trace(info, &t_key)) {
        return;
    }

    if (info->delayed &&
        (current_key->extra_id != t_key.extra_id || current_key->p_key.tid != t_key.p_key.tid ||
         current_key->p_key.pid != t_key.p_key.pid || current_key->p_key.ns != t_key.p_key.ns)) {
        bpf_dbg_printk("Skipping delayed server thread trace cleanup from non-owner tid=%d",
                       current_key->p_key.tid);
        return;
    }

    int res = bpf_map_delete_elem(&server_traces, &t_key);
    bpf_dbg_printk("Deleting server thread trace for tid=%d, res=%d", t_key.p_key.tid, res);
}
