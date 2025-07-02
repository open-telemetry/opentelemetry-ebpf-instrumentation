#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

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
    k_large_buf_max_size = 1 << 14, // 16K
    k_large_buf_max_size_mask = k_large_buf_max_size - 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, struct mysql_state_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} mysql_state SEC(".maps");

SCRATCH_MEM_SIZED(mysql_large_buffers, k_large_buf_max_size);

static __always_inline int mysql_store_state_data(const connection_info_t *conn_info,
                                                  const unsigned char *data,
                                                  size_t data_len) {
    if (data_len != k_mysql_hdr_without_command_size) {
        return 0;
    }

    struct mysql_state_data *state_data = bpf_map_lookup_elem(&mysql_state, conn_info);
    if (state_data == NULL) {
        // State data not found, treat this data as a header.
        struct mysql_state_data new_state_data = {};
        bpf_probe_read(&new_state_data, k_mysql_hdr_without_command_size, (const void *)data);
        bpf_map_update_elem(&mysql_state, conn_info, &new_state_data, BPF_ANY);
        return -1;
    }

    // This is a payload.
    return 0;
}

static __always_inline int mysql_parse_fixup_header(const connection_info_t *conn_info,
                                                    struct mysql_hdr *hdr,
                                                    const unsigned char *data,
                                                    size_t data_len) {
    struct mysql_state_data *state_data = bpf_map_lookup_elem(&mysql_state, conn_info);
    if (state_data != NULL) {
        __builtin_memcpy(hdr, state_data, k_mysql_hdr_without_command_size);
        bpf_probe_read(&hdr->command_id, k_mysql_hdr_command_id_size, (const void *)data);
        hdr->hdr_arrived = true;
    } else {
        if (data_len < k_mysql_hdr_size) {
            bpf_dbg_printk("mysql_parse_fixup_header: data_len is too short: %d", data_len);
            return -1;
        }
        bpf_probe_read(hdr, k_mysql_hdr_size, (const void *)data);
    }
    return 0;
}

// This is an alternative version of mysql_parse_fixup_header that fills the buffer
// without reading header fields.
static __always_inline int mysql_read_fixup_buffer(const connection_info_t *conn_info,
                                                   unsigned char *buf,
                                                   u32 *buf_len,
                                                   const unsigned char *data,
                                                   u32 data_len) {
    u8 offset = 0;
    const u8 buf_len_mask =
        mysql_buffer_size - 1; // mysql_buffer_size is guaranteed to be a power of 2

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

static __always_inline void mysql_send_large_buffer(tcp_req_t *req,
                                                    pid_connection_info_t *pid_conn,
                                                    const void *u_buf,
                                                    u32 bytes_len,
                                                    u8 direction) {
    if (mysql_store_state_data(&pid_conn->conn, u_buf, bytes_len) < 0) {
        bpf_dbg_printk("mysql_send_large_buffer: 4 bytes packet, storing state data");
        return;
    }

    if (bytes_len < (k_mysql_hdr_size + 1)) {
        bpf_dbg_printk("mysql_send_large_buffer: bytes_len is too short: %d", bytes_len);
        return;
    }

    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)mysql_large_buffers_mem();
    if (!large_buf) {
        bpf_dbg_printk("mysql_send_large_buffer: failed to reserve space for MySQL large buffer");
        return;
    }

    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->direction = direction;
    __builtin_memcpy((void *)&large_buf->tp, (void *)&req->tp, sizeof(tp_info_t));

    int written =
        mysql_read_fixup_buffer(&pid_conn->conn, large_buf->buf, &large_buf->len, u_buf, bytes_len);
    if (written < 0) {
        bpf_dbg_printk("mysql_send_large_buffer: failed to read buffer, not sending large buffer");
        return;
    }

    req->has_large_buffers = true;
    bpf_ringbuf_output(&events,
                       large_buf,
                       (sizeof(tcp_large_buffer_t) + written) & k_large_buf_max_size_mask,
                       get_flags());
}

static __always_inline u32 data_offset(struct mysql_hdr *hdr) {
    return hdr->hdr_arrived ? k_mysql_hdr_size - k_mysql_hdr_without_command_size
                            : k_mysql_hdr_size;
}

static __always_inline u32 mysql_command_offset(struct mysql_hdr *hdr) {
    return data_offset(hdr) - k_mysql_hdr_command_id_size;
}

// k_tail_protocol_mysql
SEC("kprobe/mysql")
int beyla_protocol_mysql(void *ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    bpf_dbg_printk("=== tcp_mysql_event len=%d pid=%d ===",
                   args->bytes_len,
                   pid_from_pid_tgid(bpf_get_current_pid_tgid()));

    if (mysql_store_state_data(
            &args->pid_conn.conn, (const unsigned char *)args->u_buf, args->bytes_len) < 0) {
        bpf_dbg_printk("mysql: 4 bytes packet, storing state data");
        return 0;
    }

    // Tail call back into generic TCP handler.
    // Once the header is fixed up, we can use the generic TCP handling code
    // in order to reuse all the common logic.
    bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);

    return 0;
}

static __always_inline u8 is_mysql(connection_info_t *conn_info,
                                   const unsigned char *data,
                                   u32 data_len,
                                   u8 *packet_type,
                                   enum protocol_type *protocol_type) {
    if (mysql_store_state_data(conn_info, data, (size_t)data_len) < 0) {
        bpf_dbg_printk("is_mysql: 4 bytes packet, storing state data");
        return 0;
    }

    if (data_len < (k_mysql_hdr_size + 1)) {
        bpf_dbg_printk("is_mysql: data_len is too short: %d", data_len);
        return 0;
    }

    struct mysql_hdr hdr = {};
    if (mysql_parse_fixup_header(conn_info, &hdr, data, data_len) != 0) {
        bpf_dbg_printk("is_mysql: failed to parse mysql header");
        return 0;
    }

    bpf_dbg_printk("is_mysql: payload_length=%d sequence_id=%d command_id=%d",
                   mysql_payload_length(hdr.payload_length),
                   hdr.sequence_id,
                   hdr.command_id);

    switch (hdr.command_id) {
    case k_mysql_com_query:
        //case k_mysql_com_stmt_prepare:
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
        *packet_type = PACKET_TYPE_REQUEST;
        break;
    case k_mysql_com_stmt_execute:
        // COM_STMT_EXECUTE packet structure:
        // +------------+-------------+----------------------+
        // | payload_len| sequence_id | command_id | stmt_id |
        // +------------+-------------+----------------------+
        // |    3B      |     1B      |     1B     | 4B      |
        // +------------+-------------+----------------------+
        *packet_type = PACKET_TYPE_REQUEST;
        break;
    default:
        if (*protocol_type == k_protocol_type_mysql) {
            // Check sequence ID and make sure we are processing a response.
            // If the request came in a single packet, the sequence ID will be 1 (hdr->hdr_arrived == false) or 2 (hdr->hdr_arrived == true).
            // If the request came in split packets, the sequence ID will be 2 (hdr->hdr_arrived == false) or 3 (hdr->hdr_arrived == true).
            bpf_dbg_printk("is_mysql: already identified as MySQL protocol");
            if ((hdr.sequence_id == 1 && !hdr.hdr_arrived) || hdr.sequence_id > 1) {
                *packet_type = PACKET_TYPE_RESPONSE;
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
    bpf_dbg_printk("is_mysql: mysql! command_id=%d packet_type=%d", hdr.command_id, *packet_type);
    return 1;
}
