// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "logger/bpf_dbg.h"
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/large_buffers.h>
#include <common/ringbuf.h>

#include <generictracer/maps/protocol_cache.h>

// TDS Packet Header
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/7af53667-1b72-4703-8258-7984e838f746
struct mssql_hdr {
    u8 type;
    u8 status;
    u16 length; // big-endian
    u16 spid;   // big-endian
    u8 packet_id;
    u8 window;
};

enum {
    // TDS header
    k_mssql_hdr_size = 8,
    k_mssql_messages_in_packet_max = 10,

    // TDS message types
    k_mssql_msg_sql_batch = 0x01,
    k_mssql_msg_rpc = 0x03,
    k_mssql_msg_response = 0x04,
    k_mssql_msg_login7 = 0x10,
    k_mssql_msg_prelogin = 0x12,
};

static __always_inline struct mssql_hdr mssql_parse_hdr(const unsigned char *data) {
    struct mssql_hdr hdr = {};

    bpf_probe_read(&hdr, sizeof(hdr), (const void *)data);

    // Length and SPID are big-endian
    hdr.length = bpf_ntohs(hdr.length);
    hdr.spid = bpf_ntohs(hdr.spid);

    return hdr;
}

static __always_inline u8 is_mssql(connection_info_t *conn_info,
                                   const unsigned char *data,
                                   u32 data_len,
                                   enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_mssql && *protocol_type != k_protocol_type_unknown) {
        // Already classified, not mssql.
        return 0;
    }

    if (data_len < k_mssql_hdr_size) {
        return 0;
    }

    size_t offset = 0;
    bool includes_known_command = false;

    for (u8 i = 0; i < k_mssql_messages_in_packet_max; i++) {
        if (offset + k_mssql_hdr_size > data_len) {
            break;
        }

        struct mssql_hdr hdr = mssql_parse_hdr(data + offset);

        if (hdr.length < k_mssql_hdr_size || hdr.length > data_len - offset) {
            return 0;
        }

        switch (hdr.type) {
        case k_mssql_msg_sql_batch:
        case k_mssql_msg_rpc:
        case k_mssql_msg_response:
        case k_mssql_msg_login7:
        case k_mssql_msg_prelogin:
            includes_known_command = true;
            break;
        default:
            break;
        }

        offset += hdr.length;
    }

    if (offset != data_len || !includes_known_command) {
        return 0;
    }

    *protocol_type = k_protocol_type_mssql;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);

    return 1;
}

// Emit a large buffer event for MSSQL protocol.
static __always_inline int mssql_send_large_buffer(tcp_req_t *req,
                                                   const void *u_buf,
                                                   u32 bytes_len,
                                                   u8 packet_type,
                                                   u8 direction,
                                                   enum large_buf_action action) {
    if (mssql_buffer_size == 0) {
        return 0;
    }

    bool is_request = (direction == req->direction);
    u32 expected_len = 0;

    if (!is_request) {
        // Response Phase
        u32 *expected_len_ptr = (u32 *)req->rbuf;
        if (req->resp_len > 0) {
            action = k_large_buf_action_append;
        } else if (bytes_len >= k_mssql_hdr_size) {
            struct mssql_hdr hdr = mssql_parse_hdr(u_buf);
            *expected_len_ptr = hdr.length;
            bpf_dbg_printk("mssql response: expected_len=%d", hdr.length);
        }
        expected_len = *expected_len_ptr;
    }

    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)mssql_large_buffers_mem();
    if (!large_buf) {
        if (!is_request) {
            bpf_dbg_printk(
                "mssql_send_large_buffer: failed to reserve space for MSSQL large buffer");
        }
        return 0;
    }

    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->packet_type = packet_type;
    large_buf->action = action;
    large_buf->direction = direction;
    large_buf->conn_info = req->conn_info;
    large_buf->tp = req->tp;
    large_buf->len = bytes_len < mssql_buffer_size ? bytes_len : mssql_buffer_size;

    if (!is_request && bytes_len >= mssql_buffer_size) {
        bpf_dbg_printk("WARN: mssql_send_large_buffer: buffer is full, truncating data");
    }

    u32 copy_len = large_buf->len;
    if (copy_len > k_large_buf_payload_max_size - 1) {
        copy_len = k_large_buf_payload_max_size - 1;
    }
    bpf_probe_read(large_buf->buf, copy_len & k_large_buf_payload_max_size_mask, u_buf);

    u32 total_size = sizeof(tcp_large_buffer_t) +
                     (large_buf->len > sizeof(void *) ? large_buf->len : sizeof(void *));

    req->has_large_buffers = true;
    bpf_ringbuf_output(&events, large_buf, total_size & k_large_buf_max_size_mask, get_flags());

    if (!is_request) {
        req->resp_len += bytes_len;
        if (expected_len > 0 && req->resp_len < expected_len) {
            bpf_dbg_printk("mssql response: partial, acc=%d exp=%d", req->resp_len, expected_len);
            return -1;
        }
    }

    return 0;
}
