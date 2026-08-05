// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/process_incarnation.h>

#include <maps/go_grpc_client_conns.h>

// Go's HPACK WriteField observation owns classification for both net/http2 and
// gRPC. Validate the full process incarnation so PID/tuple reuse cannot inherit
// a prior process's fail-closed marker.
static __always_inline u8 is_go_h2_client_conn(const pid_connection_info_t *conn) {
    const go_h2_client_conn_t *owner = bpf_map_lookup_elem(&go_grpc_client_conns, conn);
    return owner && process_incarnation_matches_current_exact(conn->pid, owner->process_start_time);
}

static __always_inline void mark_go_h2_client_conn(const pid_connection_info_t *conn) {
    const go_h2_client_conn_t owner = {
        .process_start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS(),
    };
    if (owner.process_start_time) {
        bpf_map_update_elem(&go_grpc_client_conns, conn, &owner, BPF_ANY);
    }
}

// Compatibility names for call sites outside the transport handoff path.
static __always_inline u8 is_go_grpc_client_conn(const pid_connection_info_t *conn) {
    return is_go_h2_client_conn(conn);
}

static __always_inline void mark_go_grpc_client_conn(const pid_connection_info_t *conn) {
    mark_go_h2_client_conn(conn);
}
