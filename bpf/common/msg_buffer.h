// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_buf_size.h>
#include <common/pin_internal.h>

enum {
    k_msg_buffer_size_max = 8192,
    k_msg_buffer_size_max_mask = k_msg_buffer_size_max - 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, unsigned char[k_msg_buffer_size_max]);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} msg_buffer_mem SEC(".maps");

// When sock_msg is installed it disables the kprobes attached to tcp_sendmsg.
// We use this data structure to provide the buffer to the tcp_sendmsg logic,
// because we can't read the bvec physical pages.
typedef struct msg_buffer {
    // This is a safety net in case there's been a CPU migration
    // and the stored buffer in the per-cpu map cannot be used anymore.
    unsigned char fallback_buf[k_kprobes_http2_buf_size];
    u16 pos;
    u16 real_size;
    // Store the CPU id used to save the buffer in `msg_buffer_mem`. This
    // will then be used as a guard in different execution contexts.
    u32 cpu_id;
} msg_buffer_t;
