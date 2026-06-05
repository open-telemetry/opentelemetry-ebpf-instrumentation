// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build obi_bpf_ignore
#pragma once
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <statsolly/types.h>

typedef struct tcp_io_accum_key {
    u64 sock_ptr;
    enum network_io_direction direction;
    u8 _pad[7];
} tcp_io_accum_key_t;

typedef struct tcp_io_accum {
    u32 bytes[k_tcp_io_batch_size];
    u8 count;
    u8 _pad[3];
} tcp_io_accum_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, tcp_io_accum_key_t);
    __type(value, tcp_io_accum_t);
} tcp_io_accum SEC(".maps");
