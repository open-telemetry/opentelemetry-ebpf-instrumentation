// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/event_defs.h>
#include <common/protocol_defs.h>

static __always_inline void init_failed_connect_tcp_req(tcp_req_t *req,
                                                        const pid_connection_info_t *pid_conn,
                                                        u16 orig_dport,
                                                        u64 connect_ts,
                                                        u64 end_ts,
                                                        u64 extra_id,
                                                        const pid_info *pid) {
    __builtin_memset(req, 0, sizeof(*req));

    req->flags = k_event_type_failed_connect;
    req->conn_info = pid_conn->conn;
    fixup_connection_info(&req->conn_info, TCP_SEND, orig_dport);
    req->ssl = 0;
    req->direction = TCP_SEND;
    req->start_monotime_ns = connect_ts;
    req->end_monotime_ns = end_ts;
    req->resp_len = 0;
    req->len = 0;
    req->req_len = req->len;
    req->extra_id = extra_id;
    req->protocol_type = k_protocol_type_unknown;
    req->pid = *pid;
    req->buf[0] = '\0';

    // The event is built at close time, but the span starts at the connect.
    // tp.ts is what should_be_in_same_transaction() compares against a
    // candidate parent's start, so it has to be the same instant the span
    // reports, or a connect made before the parent request existed passes a
    // check meant to reject exactly that.
    req->tp.ts = connect_ts;
}
