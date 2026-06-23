// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/http_info.h>
#include <common/ringbuf.h>

#include <logger/bpf_dbg.h>

#include <shared/obi_ctx.h>

#include <socktracer/helpers.h>
#include <socktracer/socket_data.h>

static __always_inline void finish_http_req(struct socket_data *sk_data) {
    bpf_dbg_enter();

    struct http_info *info = &sk_data->request.http;

    print_tp("finishing request", &info->tp);
    bpf_ringbuf_output(&events, info, sizeof(*info), get_flags());

    obi_ctx__del(sk_data->pid_tgid);

    __builtin_memset(&sk_data->request, 0, sizeof(sk_data->request));
}

static __always_inline bool handle_pending_http_req(struct socket_data *sk_data, u32 len) {
    bpf_dbg_enter();

    http_info_t *info = &sk_data->request.http;

    if (info->flags != EVENT_K_HTTP_REQUEST) {
        // not a HTTP request
        return false;
    }

    // we may have either an ongoing request or a previous unflushed
    // request

    if (info->resp_len == 0) {
        // we haven't seen any response yet, it's an ongoing request
        info->len += len;

        return true;
    }

    // found stale (previous) request, flush it out
    finish_http_req(sk_data);

    return false;
}

static __always_inline void init_http_request_common(struct socket_data *sk_data, u32 len) {
    const u64 curr_time = bpf_ktime_get_ns();

    const enum sk_type sk_type = sk_data->sk_type;

    const u8 direction = sk_type == sk_type_client ? TCP_SEND : TCP_RECV;

    http_info_t *info = &sk_data->request.http;

    info->flags = EVENT_K_HTTP_REQUEST;
    info->type = request_type(sk_data);
    info->ssl = 0;
    info->delayed = 0;
    // emit the normalized tuple so userspace sees the listening port as d_port
    info->conn_info = sk_data->sorted_conn;
    info->start_monotime_ns = curr_time;
    info->end_monotime_ns = curr_time;
    info->req_monotime_ns = sk_data->accept_time;
    info->extra_id = 0;
    info->pid = sk_data->pid_info;
    info->len = len;
    info->resp_len = 0;
    info->task_tid = sk_data->task_tid;
    info->status = 0;
    info->has_large_buffers = 0;
    info->direction = direction;
    info->submitted = 0;
}
