
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

#include <maps/ongoing_http2_connections.h>

static __always_inline u8 already_tracked_http2(const pid_connection_info_t *p_conn) {
    http2_conn_info_data_t *http2_info = bpf_map_lookup_elem(&ongoing_http2_connections, p_conn);
    return http2_info != 0;
}
