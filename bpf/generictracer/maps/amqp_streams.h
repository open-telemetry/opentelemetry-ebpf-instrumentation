// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/amqp_defs.h>
#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

typedef struct amqp_stream {
    u32 skip; // Remaining payload bytes plus the frame-end octet.
    u16 method_len;
    u16 method_target;
    unsigned char method[k_amqp_method_copy_len];
    unsigned char header[k_amqp_frame_header_len];
    u8 header_len;
    u8 frame_end_due;
    u8 _pad[3];
} amqp_stream_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, amqp_stream_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} amqp_streams SEC(".maps");
