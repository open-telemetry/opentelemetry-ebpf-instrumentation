// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/http_buf_size.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

// The frame a read ended inside of: kept whole when it fits, else the bytes of it left to skip
typedef struct h2_cut_frame {
    u32 skip;
    u16 len;
    u8 _pad[2];
    unsigned char data[k_kprobes_http2_buf_size];
} h2_cut_frame_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, h2_cut_frame_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} h2_cut_frames SEC(".maps");
