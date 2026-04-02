// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/event_defs.h>
#include <common/iov_iter.h>
#include <common/large_buffers.h>
#include <common/ringbuf.h>
#include <common/sock_port_ns.h>
#include <common/http_types.h>

#include <generictracer/maps/connection_meta_mem.h>
#include <generictracer/maps/iovec_mem.h>
#include <generictracer/maps/listening_ports.h>
#include <generictracer/maps/protocol_args_mem.h>

#define PACKET_TYPE_REQUEST 1
#define PACKET_TYPE_RESPONSE 2

static __always_inline u32 large_buf_emit_chunks(tcp_large_buffer_t *large_buf,
                                                 const void *u_buf,
                                                 u32 available_bytes) {
    const unsigned char *p = (const unsigned char *)u_buf;

    bpf_clamp_umax(available_bytes, k_large_buf_max_http_captured_bytes);

    const u32 niter = (available_bytes / k_large_buf_payload_max_size) +
                      ((available_bytes % k_large_buf_payload_max_size) > 0);

    u32 consumed_bytes = 0;

    for (u32 b = 0; b < niter; b++) {
        const u32 offset = b * k_large_buf_payload_max_size;

        u32 read_size = min(available_bytes, k_large_buf_payload_max_size);
        bpf_clamp_umax(read_size, k_large_buf_payload_max_size);

        if (bpf_probe_read(large_buf->buf, read_size, p + offset) != 0) {
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

volatile const s32 capture_header_buffer = 0;

static __always_inline bool is_listening(const u16 port, const u32 netns) {
    const struct sock_port_ns pn = {
        .port = port,
        .netns = netns,
    };

    bool *is_listening = bpf_map_lookup_elem(&listening_ports, &pn);

    return (is_listening != NULL && *is_listening);
}

static __always_inline u32 task_netns() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return (u32)BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
}

static __always_inline u8 infer_packet_type(u8 direction, u16 port) {
    const u32 netns = task_netns();
    const bool is_server = is_listening(port, netns);

    if ((direction == TCP_RECV && is_server) || (direction == TCP_SEND && !is_server)) {
        return PACKET_TYPE_REQUEST;
    }
    return PACKET_TYPE_RESPONSE;
}

static __always_inline http_connection_metadata_t *empty_connection_meta() {
    int zero = 0;
    return bpf_map_lookup_elem(&connection_meta_mem, &zero);
}

static __always_inline unsigned char *iovec_memory() {
    const u32 zero = 0;
    return bpf_map_lookup_elem(&iovec_mem, &zero);
}

static __always_inline call_protocol_args_t *protocol_args() {
    int zero = 0;
    return bpf_map_lookup_elem(&protocol_args_mem, &zero);
}

static __always_inline u8 request_type_by_direction(u8 direction, u8 packet_type) {
    if (packet_type == PACKET_TYPE_RESPONSE) {
        if (direction == TCP_RECV) {
            return EVENT_HTTP_CLIENT;
        } else {
            return EVENT_HTTP_REQUEST;
        }
    } else {
        if (direction == TCP_RECV) {
            return EVENT_HTTP_REQUEST;
        } else {
            return EVENT_HTTP_CLIENT;
        }
    }

    return 0;
}

static __always_inline http_connection_metadata_t *connection_meta_by_direction(u8 direction,
                                                                                u8 packet_type) {
    http_connection_metadata_t *meta = empty_connection_meta();
    if (!meta) {
        return 0;
    }

    meta->type = request_type_by_direction(direction, packet_type);
    task_pid(&meta->pid);

    return meta;
}

static __always_inline int read_msghdr_buf(struct msghdr *msg, unsigned char *buf, size_t max_len) {
    if (max_len == 0) {
        return 0;
    }

    iovec_iter_ctx ctx;

    struct iov_iter___dummy *iov_iter = (struct iov_iter___dummy *)&msg->msg_iter;
    get_iovec_ctx(&ctx, iov_iter);

    return read_iovec_ctx(&ctx, buf, max_len);
}
