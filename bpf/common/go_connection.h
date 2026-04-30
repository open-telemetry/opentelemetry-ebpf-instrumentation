// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

#include <maps/active_go_connections.h>

static __always_inline u8 *is_go_connection(const pid_connection_info_t *conn) {
    return (u8 *)bpf_map_lookup_elem(&active_go_connections, conn);
}

static __always_inline void mark_go_connection(const pid_connection_info_t *conn) {
    const u8 v = 1;
    bpf_map_update_elem(&active_go_connections, conn, &v, BPF_ANY);
}
