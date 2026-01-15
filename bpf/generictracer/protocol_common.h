// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/iov_iter.h>
#include <common/sock_port_ns.h>
#include <common/http_types.h>
#include <common/pin_internal.h>
#include <common/ringbuf.h>

#include <generictracer/maps/connection_meta_mem.h>
#include <generictracer/maps/iovec_mem.h>
#include <generictracer/maps/listening_ports.h>
#include <generictracer/maps/protocol_args_mem.h>

#include <logger/bpf_dbg.h>

#define PACKET_TYPE_REQUEST 1
#define PACKET_TYPE_RESPONSE 2

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
    u32 netns = task_netns();
    bool is_server = is_listening(port, netns);

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
