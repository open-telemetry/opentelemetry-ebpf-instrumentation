// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/connection_info.h>
#include <common/large_buffers.h>
#include <common/ringbuf.h>
#include <common/sql.h>

#include <generictracer/maps/protocol_cache.h>
#include <generictracer/protocol_common.h>

#include <logger/bpf_dbg.h>

// Every mysql command packet is prefixed by an header
// https://mariadb.com/kb/en/0-packet/
struct mysql_hdr {
    u8 payload_length[3];
    u8 sequence_id;
    u8 command_id;

    // Metadata
    bool hdr_arrived; // Signals whether to skip or not the first 4 bytes in the current buffer as
                      // they arrived in a previous packet.
};

struct mysql_state_data {
    u8 payload_length[3];
    u8 sequence_id;
};

static __always_inline u32 mysql_payload_length(const u8 payload_length[3]) {
    return (payload_length[0] | (payload_length[1] << 8) | (payload_length[2] << 16));
}

enum {
    // MySQL header sizes
    k_mysql_hdr_size = 5,
    k_mysql_hdr_command_id_size = 1,
    k_mysql_hdr_without_command_size = 4,

    // Command IDs
    k_mysql_com_query = 0x3,
    k_mysql_com_stmt_prepare = 0x16,
    k_mysql_com_stmt_execute = 0x17,

    // Sanity checks
    k_mysql_payload_length_max = 1 << 13, // 8K
};

_Static_assert(sizeof(struct mysql_state_data) == k_mysql_hdr_without_command_size,
               "size mismatch");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, struct mysql_state_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} mysql_state SEC(".maps");

// This function is used to store the MySQL header if it comes in split packets
// from double send.
// Given the fact that we need to store this for the duration of the full request
// (split in potentially multiple packets), we will **not** process or preserve
// any actual payloads that are exactly 4 bytes long — they are intentionally
// dropped in favor of state storage.
static __always_inline int mysql_store_state_data(const connection_info_t *conn_info,
                                                  const unsigned char *data,
                                                  size_t data_len) {
    if (data_len != k_mysql_hdr_without_command_size) {
        return 0;
    }

    struct mysql_state_data new_state_data = {};
    bpf_probe_read(&new_state_data, k_mysql_hdr_without_command_size, (const void *)data);
    bpf_map_update_elem(&mysql_state, conn_info, &new_state_data, BPF_ANY);

    return -1;
}

static __always_inline int mysql_parse_fixup_header(const connection_info_t *conn_info,
                                                    struct mysql_hdr *hdr,
                                                    const unsigned char *data,
                                                    size_t data_len) {
    // Try to parse and validate the header first.
    bpf_probe_read(hdr, k_mysql_hdr_size, (const void *)data);
    if (mysql_payload_length(hdr->payload_length) ==
        (data_len - k_mysql_hdr_without_command_size)) {
        // Header is valid and we have the full data, we can proceed.
        hdr->hdr_arrived = false;
        return 0;
    }

    // Prepend the header from state data.
    struct mysql_state_data *state_data = bpf_map_lookup_elem(&mysql_state, conn_info);
    if (state_data != NULL) {
        __builtin_memcpy(hdr, state_data, k_mysql_hdr_without_command_size);
        bpf_probe_read(&hdr->command_id, k_mysql_hdr_command_id_size, (const void *)data);
        hdr->hdr_arrived = true;
        return 0;
    }

    bpf_dbg_printk("mysql_parse_fixup_header: failed to parse mysql header");
    return -1;
}

// Emit a large buffer event for MySQL protocol.
// The return value is used to control the flow for this specific protocol.
// -1: wait additional data; 0: continue, regardless of errors.
static __always_inline int mysql_send_large_buffer(tcp_req_t *req,
                                                   pid_connection_info_t *pid_conn,
                                                   const void *u_buf,
                                                   u32 bytes_len,
                                                   u8 packet_type,
                                                   u8 direction,
                                                   enum large_buf_action action) {
    if (mysql_max_captured_bytes > k_large_buf_max_mysql_captured_bytes) {
        bpf_dbg_printk("BUG: mysql_max_captured_bytes exceeds maximum allowed value.");
    }

    // these are the bytes already sent so far
    const u32 bytes_sent =
        packet_type == PACKET_TYPE_REQUEST ? req->lb_req_bytes : req->lb_res_bytes;

    if (mysql_max_captured_bytes == 0 || bytes_sent >= mysql_max_captured_bytes || bytes_len == 0) {
        return 0;
    }

    if (mysql_store_state_data(&pid_conn->conn, u_buf, bytes_len) < 0) {
        bpf_dbg_printk("mysql_send_large_buffer: 4 bytes packet, storing state data");
        return -1;
    }

    tcp_large_buffer_t *lb = (tcp_large_buffer_t *)tcp_large_buffers_mem();

    if (!lb) {
        bpf_dbg_printk("mysql_send_large_buffer: failed to reserve space for MySQL large buffer");
        return 0;
    }

    lb->type = EVENT_TCP_LARGE_BUFFER;
    lb->packet_type = packet_type;
    lb->action = action;
    lb->direction = direction;
    lb->conn_info = pid_conn->conn;
    lb->tp = req->tp;

    u32 max_available_bytes = mysql_max_captured_bytes - bytes_sent;

    u32 consumed_bytes = 0;

    const struct mysql_state_data *state_data = bpf_map_lookup_elem(&mysql_state, &pid_conn->conn);

    // if there's state data present (i.e. the start of a mysql header), ship
    // it first
    if (state_data) {
        bpf_map_delete_elem(&mysql_state, &pid_conn->conn);

        if (max_available_bytes < k_mysql_hdr_without_command_size) {
            bpf_dbg_printk("mysql_send_state_data_large_buffer: not enough space");
            return 0;
        }

        max_available_bytes -= k_mysql_hdr_without_command_size;
        consumed_bytes += k_mysql_hdr_without_command_size;

        __builtin_memcpy(lb->buf, state_data, sizeof(*state_data));

        lb->len = sizeof(*state_data);

        _Static_assert(k_mysql_hdr_without_command_size < sizeof(void *),
                       "total_size needs to be adjusted");

        const u32 total_size = sizeof(tcp_large_buffer_t) + sizeof(void *);

        bpf_ringbuf_output(&events, lb, total_size, get_flags());

        lb->action = k_large_buf_action_append;
    }

    bpf_clamp_umax(max_available_bytes, k_large_buf_max_mysql_captured_bytes);

    const u32 available_bytes = min(bytes_len, max_available_bytes);

    consumed_bytes += large_buf_emit_chunks(lb, u_buf, available_bytes);

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

static __always_inline u32 data_offset(struct mysql_hdr *hdr) {
    return hdr->hdr_arrived ? k_mysql_hdr_size - k_mysql_hdr_without_command_size
                            : k_mysql_hdr_size;
}

static __always_inline u8 is_mysql(connection_info_t *conn_info,
                                   const unsigned char *data,
                                   u32 data_len,
                                   enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_mysql && *protocol_type != k_protocol_type_unknown) {
        // Already classified, not mysql.
        return 0;
    }

    if (mysql_store_state_data(conn_info, data, (size_t)data_len) < 0) {
        bpf_dbg_printk("is_mysql: 4 bytes packet, storing state data");
        return 0;
    }

    struct mysql_hdr hdr = {};
    if (mysql_parse_fixup_header(conn_info, &hdr, data, data_len) != 0) {
        bpf_dbg_printk("is_mysql: failed to parse mysql header");
        return 0;
    }
    const u32 payload_len = mysql_payload_length(hdr.payload_length);

    if (payload_len > k_mysql_payload_length_max) {
        bpf_dbg_printk("is_mysql: payload length is too large: %d", payload_len);
        return 0;
    }

    bpf_dbg_printk("is_mysql: payload_length=%d sequence_id=%d command_id=%d",
                   payload_len,
                   hdr.sequence_id,
                   hdr.command_id);

    switch (hdr.command_id) {
    case k_mysql_com_query:
    case k_mysql_com_stmt_prepare:
        // COM_QUERY packet structure:
        // +------------+-------------+------------------+
        // | payload_len| sequence_id | command_id | SQL |
        // +------------+-------------+------------------+
        // |    3B      |     1B      |     1B     | ... |
        // +------------+-------------+------------------+
        // COM_STMT_PREPARE packet structure:
        // +------------+-------------+----------------------+
        // | payload_len| sequence_id | command_id | SQL     |
        // +------------+-------------+----------------------+
        // |    3B      |     1B      |     1B     | ...     |
        // +------------+-------------+----------------------+
        if (find_sql_query((void *)(data + data_offset(&hdr))) == -1) {
            bpf_dbg_printk(
                "is_mysql: COM_QUERY or COM_PREPARE found, but buf doesn't contain a sql query");
            return 0;
        }
        break;
    case k_mysql_com_stmt_execute:
        // COM_STMT_EXECUTE packet structure:
        // +------------+-------------+----------------------+
        // | payload_len| sequence_id | command_id | stmt_id |
        // +------------+-------------+----------------------+
        // |    3B      |     1B      |     1B     | 4B      |
        // +------------+-------------+----------------------+
        if (*protocol_type == k_protocol_type_mysql) {
            // Already identified, mark this as a request.
            // NOTE: Trying to classify the connection based on this command
            // would be unreliable, as the check is too shallow.
            break;
        }
        return 0;
    default:
        if (*protocol_type == k_protocol_type_mysql) {
            // Check sequence ID and make sure we are processing a response.
            // If the request came in a single packet, the sequence ID will be 1 (hdr->hdr_arrived == false) or 2 (hdr->hdr_arrived == true).
            // If the request came in split packets, the sequence ID will be 2 (hdr->hdr_arrived == false) or 3 (hdr->hdr_arrived == true).
            bpf_dbg_printk("is_mysql: already identified as MySQL protocol");
            if ((hdr.sequence_id == 1 && !hdr.hdr_arrived) || hdr.sequence_id > 1) {
                break;
            }
            bpf_dbg_printk(
                "is_mysql: sequence_id is too low, most likely request with unhandled command ID");
            return 0;
        }

        bpf_dbg_printk("is_mysql: unhandled mysql command_id: %d", hdr.command_id);
        return 0;
    }

    *protocol_type = k_protocol_type_mysql;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);

    bpf_dbg_printk("is_mysql: mysql! command_id=%d", hdr.command_id);
    return 1;
}
