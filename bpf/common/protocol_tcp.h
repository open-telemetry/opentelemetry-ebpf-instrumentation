
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/connection_info.h>

#include <maps/ongoing_tcp_req.h>

static __always_inline u8 already_tracked_tcp(const pid_connection_info_t *p_conn) {
    tcp_req_t *tcp_info = bpf_map_lookup_elem(&ongoing_tcp_req, p_conn);
    return tcp_info != 0;
}
