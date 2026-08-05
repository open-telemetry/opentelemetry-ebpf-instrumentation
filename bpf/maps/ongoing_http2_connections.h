// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>

#include <generictracer/types/http2_conn_info_data.h>

enum { k_ongoing_http2_connections_map_type = BPF_MAP_TYPE_HASH };

struct {
    // Generation-checked tuple deletes are only safe when an entry cannot be
    // evicted and replaced between the comparison and delete. Explicit close
    // and lease-owner retirement keep this bounded hash reclaimed.
    __uint(type, k_ongoing_http2_connections_map_type);
    __type(key, pid_connection_info_t);
    __type(value, http2_conn_info_data_t); // flags and id
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http2_connections SEC(".maps");
