// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <maps/ongoing_http.h>

static __always_inline u8 already_tracked_http(const pid_connection_info_t *p_conn) {
    http_info_t *http_info = bpf_map_lookup_elem(&ongoing_http, p_conn);
    return (http_info && !(http_info->delayed || http_info->submitted));
}
