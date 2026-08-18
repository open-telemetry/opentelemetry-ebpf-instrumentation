// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/protocol_defs.h>
#include <common/trace_lifecycle.h>

#include <maps/ongoing_tcp_req.h>

// Shared with the HTTP parser: a connection read as an unknown protocol before
// it spoke HTTP leaves a TCP request that never completes.
static __always_inline void cleanup_trace_info(tcp_req_t *tcp, pid_connection_info_t *pid_conn) {
    if (tcp->direction == TCP_RECV) {
        trace_key_t t_key = {0};
        task_tid(&t_key.p_key);
        if (tcp->task_tid) {
            t_key.p_key.tid = tcp->task_tid;
        }
        t_key.extra_id = tcp->extra_id;

        delete_server_trace(pid_conn, &t_key);
    } else {
        delete_client_trace_info(pid_conn);
    }
}

static __always_inline void cleanup_tcp_trace_info_if_needed(pid_connection_info_t *pid_conn) {
    tcp_req_t *existing = bpf_map_lookup_elem(&ongoing_tcp_req, pid_conn);
    if (!existing) {
        return;
    }

    // only a receive-classified request left behind can latch as a server
    // parent; a send-classified one (e.g. the raw bytes of a TLS connection
    // whose decrypted stream is claiming it now) holds the connection tp that
    // black-box correlation still needs
    if (existing->direction == TCP_RECV) {
        cleanup_trace_info(existing, pid_conn);
    }
}
