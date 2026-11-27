// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/pin_internal.h>
#include <common/tcp_multiplex.h>

enum {
    k_tcp_multiplex_max_operations = 1 + 32, // initial I/O and up to 32 appends
    k_tcp_multiplex_max_records = 1024,
};

typedef struct {
    tcp_req_t tcp;
    tcp_multiplex_header_t header;
    tcp_io_range_t operations[k_tcp_multiplex_max_operations];
} tcp_multiplex_record_t;

typedef struct {
    u64 start;
    u32 pid;
    connection_info_t conn;
} tcp_multiplex_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, tcp_multiplex_key_t);
    __type(value, tcp_multiplex_record_t);
    __uint(max_entries, k_tcp_multiplex_max_records);
    __uint(pinning, OBI_PIN_INTERNAL);
} tcp_multiplex_records SEC(".maps");
