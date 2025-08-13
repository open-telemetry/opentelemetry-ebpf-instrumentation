// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(
        key,
        partial_connection_info_t); // key: the connection info without the destination address, but with the tcp sequence
    __type(value, connection_info_t); // value: traceparent info
    __uint(max_entries, 1024);
} tcp_connection_map SEC(".maps");
