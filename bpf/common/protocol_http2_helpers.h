
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/process_incarnation.h>
#include <common/protocol_defs.h>
#include <common/sock_port_ns.h>

#include <maps/ongoing_http2_connections.h>
#include <maps/connection_tracker.h>

static __always_inline http2_conn_info_data_t *
current_http2_connection(const pid_connection_info_t *p_conn) {
    http2_conn_info_data_t *http2_info = bpf_map_lookup_elem(&ongoing_http2_connections, p_conn);
    if (!http2_info || http2_info->retired || !http2_info->connection_time ||
        !process_incarnation_matches_current_exact(p_conn->pid, http2_info->process_start_time)) {
        return NULL;
    }
    const tracked_connection_t *tracked = bpf_map_lookup_elem(&connection_tracker, &p_conn->conn);
    if (!tracked || tracked->time != http2_info->connection_time ||
        tracked->netns != task_netns()) {
        return NULL;
    }
    return http2_info;
}

static __always_inline u8 already_tracked_http2(const pid_connection_info_t *p_conn) {
    return current_http2_connection(p_conn) != NULL;
}

// Known TLS HTTP/2 conns — on-the-wire payload is ciphertext, never sniff or inject
static __always_inline u8 already_tracked_ssl_http2(const pid_connection_info_t *p_conn) {
    http2_conn_info_data_t *h2 = current_http2_connection(p_conn);
    return h2 && (h2->flags & WITH_SSL);
}
