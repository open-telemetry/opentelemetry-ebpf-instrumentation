// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

#include <maps/go_grpc_client_conns.h>

// Marks Go gRPC client conns only — gotracer's grpcFramerWriteHeaders writes
// HPACK in user buffer, sk_msg must skip to avoid double injection
static __always_inline u8 *is_go_grpc_client_conn(const pid_connection_info_t *conn) {
    return (u8 *)bpf_map_lookup_elem(&go_grpc_client_conns, conn);
}

static __always_inline void mark_go_grpc_client_conn(const pid_connection_info_t *conn) {
    bpf_map_update_elem(&go_grpc_client_conns, conn, &(u8){1}, BPF_ANY);
}
