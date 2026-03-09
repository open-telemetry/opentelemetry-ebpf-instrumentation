// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

#include <maps/active_ssl_connections.h>

static __always_inline u64 *is_ssl_connection(pid_connection_info_t *conn) {
    return (u64 *)bpf_map_lookup_elem(&active_ssl_connections, conn);
}
