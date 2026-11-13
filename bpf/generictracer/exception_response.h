// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/event_defs.h>
#include <common/exception_emit.h>
#include <common/http_info.h>

#include <generictracer/python_exception.h>

enum { k_http_status_final = 200, k_http_status_server_error = 500 };

// Emits a pending exception for a 5xx server response and clears it for other final responses.
static __always_inline void exception_on_server_response(const http_info_t *info) {
    if (!g_exceptions_enabled || info->type != k_event_type_http_request ||
        info->status < k_http_status_final) {
        return;
    }

    if (info->status >= k_http_status_server_error) {
        python_exception_emit(info->pid.host_pid, &info->tp, info->start_monotime_ns);
    } else {
        python_exception_key_t key = {.pid = info->pid.host_pid};
        __builtin_memcpy(key.span_id, info->tp.span_id, sizeof(key.span_id));
        bpf_map_delete_elem(&python_exception_pending, &key);
    }
}
