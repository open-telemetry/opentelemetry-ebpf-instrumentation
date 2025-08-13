#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/http_types.h>
#include <common/pin_internal.h>
#include <common/ringbuf.h>
#include <common/runtime.h>
#include <common/scratch_mem.h>
#include <common/sql.h>
#include <common/tp_info.h>
#include <common/trace_common.h>

#include <generictracer/protocol_common.h>
#include <generictracer/k_tracer_tailcall.h>

#include <generictracer/maps/protocol_cache.h>

#include <maps/active_ssl_connections.h>

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

    // Large buffer
    k_mysql_large_buf_max_size = 1 << 14, // 16K
    k_mysql_large_buf_max_size_mask = k_mysql_large_buf_max_size - 1,

    // Sanity checks
    k_mysql_payload_length_max = 1 << 13, // 8K
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, struct mysql_state_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} mysql_state SEC(".maps");

SCRATCH_MEM_SIZED(mysql_large_buffers, k_mysql_large_buf_max_size);

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

// This is an alternative version of mysql_parse_fixup_header that fills the buffer
// without reading header fields.
static __always_inline int mysql_read_fixup_buffer(const connection_info_t *conn_info,
                                                   unsigned char *buf,
                                                   u32 *buf_len,
                                                   const unsigned char *data,
                                                   u32 data_len) {
    u8 offset = 0;

    if (!is_pow2(mysql_buffer_size)) {
        bpf_dbg_printk("mysql_read_fixup_buffer: bug: mysql_buffer_size is not a power of 2");
        return -1;
    }
    const u8 buf_len_mask = mysql_buffer_size - 1;

    struct mysql_state_data *state_data = bpf_map_lookup_elem(&mysql_state, conn_info);
    if (state_data != NULL) {
        bpf_probe_read(buf, k_mysql_hdr_without_command_size, (const void *)state_data);
        offset += k_mysql_hdr_without_command_size;
        bpf_map_delete_elem(&mysql_state, conn_info);
    } else {
        if (data_len < k_mysql_hdr_size) {
            bpf_dbg_printk("mysql_read_fixup_buffer: data_len is too short: %d", data_len);
            return -1;
        }
    }

    *buf_len = data_len + offset;
    if (*buf_len >= mysql_buffer_size) {
        *buf_len = mysql_buffer_size;
        bpf_dbg_printk("WARN: mysql_read_fixup_buffer: buffer is full, truncating data");
    }

    bpf_probe_read(buf + offset, *buf_len & buf_len_mask, (const void *)data);

    return *buf_len;
}

// Emit a large buffer event for MySQL protocol.
// The return value is used to control the flow for this specific protocol.
// -1: wait additional data; 0: continue, regardless of errors.
static __always_inline int mysql_send_large_buffer(tcp_req_t *req,
                                                   pid_connection_info_t *pid_conn,
                                                   const void *u_buf,
                                                   u32 bytes_len,
                                                   u8 packet_type,
                                                   enum large_buf_action action) {
    if (mysql_store_state_data(&pid_conn->conn, u_buf, bytes_len) < 0) {
        bpf_dbg_printk("mysql_send_large_buffer: 4 bytes packet, storing state data");
        return -1;
    }

    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)mysql_large_buffers_mem();
    if (!large_buf) {
        bpf_dbg_printk("mysql_send_large_buffer: failed to reserve space for MySQL large buffer");
        return 0;
    }

    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->packet_type = packet_type;
    large_buf->action = action;
    __builtin_memcpy((void *)&large_buf->tp, (void *)&req->tp, sizeof(tp_info_t));

    int written =
        mysql_read_fixup_buffer(&pid_conn->conn, large_buf->buf, &large_buf->len, u_buf, bytes_len);
    if (written < 0) {
        bpf_dbg_printk("mysql_send_large_buffer: failed to read buffer, not sending large buffer");
        return 0;
    }

    u32 total_size = sizeof(tcp_large_buffer_t);
    total_size += written > sizeof(void *) ? written : sizeof(void *);

    req->has_large_buffers = true;
    bpf_ringbuf_output(
        &events, large_buf, total_size & k_mysql_large_buf_max_size_mask, get_flags());
    return 0;
}

static __always_inline u32 data_offset(struct mysql_hdr *hdr) {
    return hdr->hdr_arrived ? k_mysql_hdr_size - k_mysql_hdr_without_command_size
                            : k_mysql_hdr_size;
}

static __always_inline u32 mysql_command_offset(struct mysql_hdr *hdr) {
    return data_offset(hdr) - k_mysql_hdr_command_id_size;
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
