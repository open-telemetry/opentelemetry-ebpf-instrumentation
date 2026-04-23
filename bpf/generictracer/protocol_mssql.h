// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <logger/bpf_dbg.h>
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/large_buffers.h>
#include <common/ringbuf.h>

#include <generictracer/maps/protocol_cache.h>
#include <generictracer/protocol_common.h>

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

    // TDS status bits
    k_mssql_status_eom = 0x01, // End Of Message

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
        // Login/prelogin packets are accepted here to classify the connection
        // early (before any SQL is sent). They carry no SQL and are never
        // processed by the Go-side parser, which intentionally omits them.
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

// Tracks accumulated response length and detects the TDS End-Of-Message bit.
// Returns -1 to wait for more data, 0 when the response is complete.
static __always_inline int mssql_response_eom(tcp_req_t *req, const void *u_buf, u32 bytes_len) {
    if (req->resp_len == 0 && bytes_len >= k_mssql_hdr_size) {
        bpf_probe_read(req->rbuf, k_mssql_hdr_size, u_buf);
    }

    req->resp_len += bytes_len;

    // Scan complete TDS packets in the current recv buffer for the EOM bit.
    // A response may arrive as: (a) one or more complete packets in a single
    // recv, or (b) a single packet split across multiple recvs (header first,
    // then payload). Handle both by falling back to accumulated-length tracking
    // when the current buffer does not start at a TDS packet boundary.
    bool eom = false;
    bool found_complete_packet = false;
    u32 offset = 0;
    for (u8 i = 0; i < k_mssql_messages_in_packet_max; i++) {
        if (offset + k_mssql_hdr_size > bytes_len) {
            break;
        }
        const struct mssql_hdr hdr = mssql_parse_hdr((const unsigned char *)u_buf + offset);
        if (hdr.length < k_mssql_hdr_size || offset + hdr.length > bytes_len) {
            break;
        }
        found_complete_packet = true;
        if (hdr.status & k_mssql_status_eom) {
            eom = true;
        }
        offset += hdr.length;
    }

    if (eom) {
        return 0;
    } else if (found_complete_packet) {
        // Complete packets present but no EOM: more packets expected.
        bpf_dbg_printk("mssql response: waiting for EOM, acc=%d", req->resp_len);
        return -1;
    }

    // Could not parse a complete TDS packet (partial recv or payload
    // continuation). Fall back to length tracking using the saved header.
    if (req->resp_len < k_mssql_hdr_size) {
        return -1;
    }
    const struct mssql_hdr first_hdr = mssql_parse_hdr(req->rbuf);
    if (first_hdr.length >= k_mssql_hdr_size) {
        const u32 prev_resp_len = req->resp_len - bytes_len;
        // Wait while packet 1 is still completing, or if it just finished
        // in this recv with no EOM (more packets follow; the next recv
        // will start at a TDS boundary where the main loop detects EOM).
        if (prev_resp_len < first_hdr.length &&
            (req->resp_len < first_hdr.length || !(first_hdr.status & k_mssql_status_eom))) {
            bpf_dbg_printk(
                "mssql response: partial, acc=%d exp=%d", req->resp_len, first_hdr.length);
            return -1;
        }
    }

    return 0;
}

// Emit a large buffer event for MSSQL protocol.
static __always_inline void mssql_send_large_buffer(tcp_req_t *req,
                                                    const void *u_buf,
                                                    u32 bytes_len,
                                                    u8 packet_type,
                                                    u8 direction,
                                                    enum large_buf_action action) {
    if (mssql_max_captured_bytes > k_large_buf_max_mssql_captured_bytes) {
        bpf_dbg_printk("BUG: mssql_max_captured_bytes exceeds maximum allowed value.");
    }

    const u32 bytes_sent =
        packet_type == PACKET_TYPE_REQUEST ? req->lb_req_bytes : req->lb_res_bytes;

    if (mssql_max_captured_bytes > 0 && bytes_sent < mssql_max_captured_bytes && bytes_len > 0) {
        tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)tcp_large_buffers_mem();
        if (!large_buf) {
            bpf_dbg_printk(
                "mssql_send_large_buffer: failed to reserve space for MSSQL large buffer");
            return;
        }

        large_buf->type = EVENT_TCP_LARGE_BUFFER;
        large_buf->packet_type = packet_type;
        large_buf->action = action;
        large_buf->direction = direction;
        large_buf->conn_info = req->conn_info;
        large_buf->tp = req->tp;

        u32 max_available_bytes = mssql_max_captured_bytes - bytes_sent;
        bpf_clamp_umax(max_available_bytes, k_large_buf_max_mssql_captured_bytes);

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
    }
}
