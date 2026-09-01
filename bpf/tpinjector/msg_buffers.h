// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/algorithm.h>
#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/http_buf_size.h>
#include <common/http_types.h>
#include <common/msg_buffer.h>
#include <common/protocol_http_helpers.h>
#include <common/protocol_http2_helpers.h>
#include <common/protocol_tcp_helpers.h>
#include <common/ssl_connection.h>

#include <pid/pid_helpers.h>

#include <logger/bpf_dbg.h>

#include <maps/msg_buffers.h>

static __always_inline u8 already_tracked(const pid_connection_info_t *p_conn) {
    return already_tracked_http(p_conn) || already_tracked_tcp(p_conn) ||
           already_tracked_http2(p_conn);
}

// This code is copied from the kprobe on tcp_sendmsg and it's called from
// the sock_msg program, which does the packet extension for injecting the
// Traceparent. Since the sock_msg runs before the kprobe on tcp_sendmsg, we
// need to extend the packet before we'll have the opportunity to setup the
// outgoing_trace_map metadata. We can directly perhaps run the same code that
// the kprobe on tcp_sendmsg does, but it's complicated, no tail calls from
// sock_msg programs and inlining will eventually hit us with the instruction
// limit when we eventually add HTTP2/gRPC support.
// Populates msg_buffers / msg_buffer_mem for the kprobe on tcp_sendmsg,
// which runs after sk_msg. Bails on size=0, SSL, or allocation failure.
static __always_inline bool fill_msg_buffers(struct sk_msg_md *msg,
                                             const pid_connection_info_t *p_conn,
                                             const egress_key_t *e_key) {
    if (msg->size == 0 || is_ssl_connection(p_conn)) {
        return false;
    }

    msg_buffer_t msg_buf = {
        .pos = 0,
        .real_size = min(msg->size, k_msg_buffer_size_max),
        .cpu_id = bpf_get_smp_processor_id(),
    };

    bpf_probe_read_kernel(msg_buf.fallback_buf, k_kprobes_http2_buf_size, msg->data);

    const u16 copy_bytes = max(msg_buf.real_size, k_kprobes_http2_buf_size);

    unsigned char **msg_ptr = bpf_map_lookup_elem(&msg_buffer_mem, &(u32){0});

    if (!msg_ptr) {
        bpf_d_printk("failed to reserve msg_buffer space [%s]", __FUNCTION__);
        return false;
    }

    msg_ptr[0] = 0;
    bpf_probe_read_kernel(msg_ptr, copy_bytes & k_msg_buffer_size_max_mask, msg->data);
    bpf_map_update_elem(&msg_buffer_mem, &(u32){0}, msg_ptr, BPF_ANY);

    // We setup any call that looks like HTTP request to be extended.
    // This must match exactly to what the decision will be for
    // the kprobe program on tcp_sendmsg, which sets up the
    // outgoing_trace_map data used by Traffic Control to write the
    // actual 'Traceparent:...' string.

    if (bpf_map_update_elem(&msg_buffers, e_key, &msg_buf, BPF_ANY)) {
        // fail if we can't setup a msg buffer
        return false;
    }

    return true;
}

static __always_inline u8 protocol_detector(struct sk_msg_md *msg,
                                            u64 id,
                                            const connection_info_t *conn) {
    bpf_dbg_printk("id=%d, size=%d", id, msg->size);

    pid_connection_info_t p_conn = {};
    bpf_memcpy(&p_conn.conn, conn, sizeof(connection_info_t));

    dbg_print_http_connection_info(&p_conn.conn);
    sort_connection_info(&p_conn.conn);
    p_conn.pid = pid_from_pid_tgid(id);

    if (already_tracked(&p_conn)) {
        bpf_dbg_printk("already extended before, ignoring this packet...");
        return 0;
    }

    unsigned char **msg_ptr = bpf_map_lookup_elem(&msg_buffer_mem, &(u32){0});

    if (!msg_ptr) {
        return 0;
    }

    if (is_http_request_buf((const unsigned char *)msg_ptr)) {
        bpf_dbg_printk("setting up request to be extended");

        return 1;
    }

    return 0;
}
