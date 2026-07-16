// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/large_buffers.h>
#include <common/ringbuf.h>

enum large_buf_read_mode {
    k_large_buf_read_kernel = 0,
    k_large_buf_read_user = 1,
};

static __always_inline u32 large_buf_emit_chunks(tcp_large_buffer_t *large_buf,
                                                 const void *u_buf,
                                                 u32 available_bytes,
                                                 enum large_buf_read_mode mode) {
    const unsigned char *p = (const unsigned char *)u_buf;

    bpf_clamp_umax(available_bytes, k_large_buf_per_emit_max);

    const u32 niter = (available_bytes / k_large_buf_payload_max_size) +
                      ((available_bytes % k_large_buf_payload_max_size) > 0);

    u32 consumed_bytes = 0;

    for (u32 b = 0; b < niter; b++) {
        const u32 offset = b * k_large_buf_payload_max_size;

        u32 read_size = min(available_bytes, k_large_buf_payload_max_size);
        bpf_clamp_umax(read_size, k_large_buf_payload_max_size);

        const long read_err = (mode == k_large_buf_read_user)
                                  ? bpf_probe_read_user(large_buf->buf, read_size, p + offset)
                                  : bpf_probe_read(large_buf->buf, read_size, p + offset);

        if (read_err != 0) {
            break;
        }

        large_buf->len = read_size;

        u32 payload_size = max(read_size, sizeof(void *));
        bpf_clamp_umax(payload_size, k_large_buf_payload_max_size);
        u32 total_size = sizeof(tcp_large_buffer_t) + payload_size;
        bpf_clamp_umax(total_size, k_large_buf_max_size);

        if (bpf_ringbuf_output(&events, large_buf, total_size, get_flags()) != 0) {
            break;
        }

        available_bytes -= read_size;
        consumed_bytes += read_size;
        large_buf->action = k_large_buf_action_append;
    }

    return consumed_bytes;
}
