// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Host-test shadow of common/msg_buffer.h: keeps the sizes and the
// msg_buffer_t layout the code under test depends on, and replaces the
// per-CPU array with a mock map the test owns.
#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_buf_size.h>

enum {
    k_msg_buffer_size_max = 8192,
    k_msg_buffer_size_max_mask = k_msg_buffer_size_max - 1,
};

extern struct bpf_test_map msg_buffer_mem;

typedef struct msg_buffer {
    unsigned char fallback_buf[k_kprobes_http2_buf_size];
    u16 pos;
    u16 real_size;
    u32 cpu_id;
} msg_buffer_t;
