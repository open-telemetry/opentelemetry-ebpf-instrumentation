// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/tp_info.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(
        key,
        nat_partial_connection_info_t); // key: destination tuple plus TCP seq/ack that survives source NAT
    __type(value, tp_info_pid_t); // value: client trace info
    __uint(max_entries, 1024);
} tcp_nat_trace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(
        key,
        nat_http_partial_connection_info_t); // key: destination tuple plus HTTP request prefix that survives NAT/proxy rewrites
    __type(value, tp_info_pid_t); // value: client trace info
    __uint(max_entries, 1024);
} http_nat_trace_map SEC(".maps");
