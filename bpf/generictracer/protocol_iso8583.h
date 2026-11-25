// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/http_types.h>
#include <common/ringbuf.h>

#include <maps/ongoing_tcp_req.h>

#include <generictracer/maps/tcp_req_mem.h>
#include <generictracer/protocol_common.h>

enum {
    k_iso8583_version_2003 = 2,
    k_iso8583_class_authorization = 1,
    k_iso8583_class_network_management = 8,
    k_iso8583_function_instruction_ack = 7,
    k_iso8583_origin_other_repeat = 5,
    k_iso8583_function_response_bit = 1, // Odd functions are responses or acknowledgements.
    k_iso8583_field7_bit = 0x02,
    k_iso8583_invalid_hex = 0xff,
    k_iso8583_ascii_min = 4 + 16 + 10, // MTI, bitmap and DE7
    k_iso8583_packed_min = 2 + 8 + 5,
};

static __always_inline u8 iso8583_hex_nibble(u8 c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    c |= 0x20;

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    return k_iso8583_invalid_hex;
}

static __always_inline bool iso8583_response_mti(u8 version, u8 class, u8 function, u8 origin) {
    return version <= k_iso8583_version_2003 && class >= k_iso8583_class_authorization &&
           class <= k_iso8583_class_network_management &&
           function <= k_iso8583_function_instruction_ack &&
           (function & k_iso8583_function_response_bit) && origin <= k_iso8583_origin_other_repeat;
}

static __always_inline bool iso8583_response_header(const unsigned char *body, u32 size) {
    if (body[0] >= '0' && body[0] <= '0' + k_iso8583_version_2003) {
        const u8 low = iso8583_hex_nibble(body[5]);

        return size >= k_iso8583_ascii_min &&
               iso8583_hex_nibble(body[4]) != k_iso8583_invalid_hex &&
               low != k_iso8583_invalid_hex && (low & k_iso8583_field7_bit) &&
               iso8583_response_mti(body[0] - '0', body[1] - '0', body[2] - '0', body[3] - '0');
    }

    return size >= k_iso8583_packed_min && (body[2] & k_iso8583_field7_bit) &&
           iso8583_response_mti(body[0] >> 4, body[0] & 0xf, body[1] >> 4, body[1] & 0xf);
}

// Userspace validates the remaining bitmaps, field layout and transmission time.
static __always_inline bool iso8583_timed_response(const unsigned char *data, int len) {
    if (len < 2 + k_iso8583_packed_min) {
        return false;
    }

    const u32 available = (u32)len;
    const u32 size = ((u32)data[0] << 8) | data[1];

    if (size + 2 <= available && iso8583_response_header(data + 2, size)) {
        return true;
    }

    u32 ascii_size = 0;
    for (u8 i = 0; i < 4; ++i) {
        if (data[i] < '0' || data[i] > '9') {
            return false;
        }

        ascii_size = ascii_size * 10 + (data[i] - '0');
    }

    return ascii_size + 4 <= available && iso8583_response_header(data + 4, ascii_size);
}

static __always_inline void maybe_emit_iso8583_response(const call_protocol_args_t *args) {
    const tcp_req_t *pending = bpf_map_lookup_elem(&ongoing_tcp_req, &args->pid_conn);
    if (pending && pending->protocol_type != k_protocol_type_unknown) {
        return;
    }

    // An opposite-direction reply completes the pending exchange. In the same direction,
    // the write may carry an ISO frame inside another protocol's payload.
    if (pending && !pending->end_monotime_ns &&
        (pending->direction != args->direction ||
         !iso8583_timed_response(pending->buf, pending->req_len))) {
        return;
    }

    tcp_req_t *event = tcp_req_mem();
    if (!event) {
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));

    u32 captured = (u32)args->bytes_len;
    bpf_clamp_umax(captured, sizeof(event->buf));

    // The common TCP path receives both userspace and kernel-backed buffers.
    if (bpf_probe_read(event->buf, captured, (const void *)args->u_buf) != 0) {
        return;
    }

    event->flags = k_event_type_tcp_request;
    event->protocol_type = k_protocol_type_iso8583;
    event->event_source = event_source(args->lw_thread);
    event->direction = args->direction;
    event->ssl = args->ssl;
    event->conn_info = args->pid_conn.conn;

    fixup_connection_info(&event->conn_info, args->direction, args->orig_dport);
    task_pid(&event->pid);

    event->len = captured;
    event->req_len = (u32)args->bytes_len;
    event->start_monotime_ns = bpf_ktime_get_ns();
    event->end_monotime_ns = event->start_monotime_ns;

    events_ringbuf_output(event, sizeof(*event));
}
