// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/connection_info.h>
#include <common/large_buffers.h>
#include <common/ringbuf.h>

#include <generictracer/maps/protocol_cache.h>
#include <generictracer/protocol_common.h>

struct postgres_hdr {
    u32 message_len;
    u8 message_type;
    u8 _pad[3];
};

enum {
    // Postgres header
    k_pg_hdr_size = 5,
    k_pg_messages_in_packet_max = 10,

    // Postgres frontend message types
    k_pg_msg_bind = 'B',    // Bind a named portal to a prepared statement
    k_pg_msg_execute = 'E', // Execute a portal
    k_pg_msg_parse = 'P',   // Parses a query and creates a prepared statement
    k_pg_msg_query = 'Q',   // Executes a simple SQL query
};

// Emit a large buffer event for Postgres protocol.
// The return value is used to control the flow for this specific protocol.
// -1: wait additional data; 0: continue, regardless of errors.
static __always_inline int postgres_send_large_buffer(tcp_req_t *req,
                                                      const void *u_buf,
                                                      u32 bytes_len,
                                                      u8 packet_type,
                                                      u8 direction,
                                                      enum large_buf_action action) {
    if (postgres_max_captured_bytes > k_large_buf_max_postgres_captured_bytes) {
        bpf_dbg_printk("BUG: postgres_max_captured_bytes exceeds maximum allowed value.");
    }

    const u32 bytes_sent =
        packet_type == PACKET_TYPE_REQUEST ? req->lb_req_bytes : req->lb_res_bytes;

    if (postgres_max_captured_bytes == 0 || bytes_sent >= postgres_max_captured_bytes ||
        bytes_len == 0) {
        return 0;
    }

    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)tcp_large_buffers_mem();
    if (!large_buf) {
        bpf_dbg_printk(
            "postgres_send_large_buffer: failed to reserve space for Postgres large buffer");
        return 0;
    }

    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->packet_type = packet_type;
    large_buf->action = action;
    large_buf->direction = direction;
    large_buf->conn_info = req->conn_info;
    large_buf->tp = req->tp;

    u32 max_available_bytes = postgres_max_captured_bytes - bytes_sent;

    bpf_clamp_umax(max_available_bytes, k_large_buf_max_postgres_captured_bytes);

    const u32 available_bytes = min(bytes_len, max_available_bytes);

    const u32 consumed_bytes = large_buf_emit_chunks(large_buf, u_buf, available_bytes);

    if (packet_type == PACKET_TYPE_REQUEST) {
        req->lb_req_bytes += consumed_bytes;
    } else {
        req->lb_res_bytes += consumed_bytes;
    }

    if (consumed_bytes > 0) {
        req->has_large_buffers = true;
    }

    return 0;
}

static __always_inline struct postgres_hdr postgres_parse_hdr(const unsigned char *data) {
    struct postgres_hdr hdr = {};

    u8 header[k_pg_hdr_size] = {};
    bpf_probe_read(header, k_pg_hdr_size, data);

    u32 message_len_le;
    __builtin_memcpy(&message_len_le, header + 1, sizeof(message_len_le));

    hdr.message_type = header[0];
    hdr.message_len = bpf_ntohl(message_len_le);

    return hdr;
}

static __always_inline u8 is_postgres(connection_info_t *conn_info,
                                      const unsigned char *data,
                                      u32 data_len,
                                      enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_postgres && *protocol_type != k_protocol_type_unknown) {
        // Already classified, not postgres.
        return 0;
    }

    if (data_len < k_pg_hdr_size) {
        bpf_dbg_printk("is_postgres: data_len is too short: %d", data_len);
        return 0;
    }

    size_t message_size = 0;
    struct postgres_hdr hdr;
    bool includes_known_command = false;

    for (u8 i = 0; i < k_pg_messages_in_packet_max; i++) {
        if (message_size + k_pg_hdr_size > data_len) {
            break;
        }

        hdr = postgres_parse_hdr(data + message_size);

        message_size += hdr.message_len + 1;
        if (hdr.message_len == 0) {
            break;
        }

        switch (hdr.message_type) {
        case k_pg_msg_query:
        case k_pg_msg_parse:
        case k_pg_msg_bind:
        case k_pg_msg_execute:
            includes_known_command = true;
            break;
        default:
            break;
        }
    }

    if (message_size != data_len) {
        bpf_dbg_printk("is_postgres: message length mismatch: message_size=%d data_len=%u",
                       message_size,
                       data_len);
        return 0;
    }

    if (!includes_known_command) {
        bpf_dbg_printk("is_postgres: no known command found");
        return 0;
    }

    *protocol_type = k_protocol_type_postgres;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);

    bpf_dbg_printk("is_postgres: postgres! message_type=%u", hdr.message_type);
    return 1;
}
