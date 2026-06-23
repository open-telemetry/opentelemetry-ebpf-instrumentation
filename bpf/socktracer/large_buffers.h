// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/large_buffers.h>
#include <common/ringbuf.h>
#include <common/tp_info.h>

#include <logger/bpf_dbg.h>

#include <socktracer/common_defs.h>

// emit_large_buffer_chunks sends data in k_large_buf_payload_max_size chunks.
// Used by egress where ctx_data() may span more than one chunk.
static __always_inline u32 emit_large_buffer_chunks(tcp_large_buffer_t *buf,
                                                    const unsigned char *data,
                                                    const unsigned char *data_end,
                                                    u32 remaining_len) {
    const u8 nbuffers = (remaining_len / k_large_buf_payload_max_size) +
                        (remaining_len % k_large_buf_payload_max_size != 0);

    u32 offset = 0;

    for (u8 i = 0; i < nbuffers; ++i) {
        const u32 read_len = min(remaining_len, (u32)k_large_buf_payload_max_size);
        const u32 payload_size = max(read_len, (u32)sizeof(void *));
        const u32 total_size = sizeof(tcp_large_buffer_t) + payload_size;

        if (data + offset + read_len > data_end) {
            break;
        }

        bpf_probe_read_kernel(buf->buf, read_len, data + offset);
        buf->len = read_len;

        if (bpf_ringbuf_output(&events, buf, total_size, get_flags()) != 0) {
            break;
        }

        buf->action = k_large_buf_action_append;
        offset += read_len;
        remaining_len -= read_len;
    }

    return offset;
}

// prepare_large_buffer_header fills the common header fields into *buf.
static __always_inline tcp_large_buffer_t *prepare_large_buffer_header(
    u8 packet_type, u8 direction, connection_info_t conn_info, tp_info_t tp, u8 action) {
    tcp_large_buffer_t *buf = (tcp_large_buffer_t *)tcp_large_buffers_mem();
    if (!buf) {
        return NULL;
    }

    buf->type = EVENT_TCP_LARGE_BUFFER;
    buf->packet_type = packet_type;
    buf->direction = direction;
    buf->conn_info = conn_info;
    buf->action = action;
    buf->tp = tp;

    return buf;
}
