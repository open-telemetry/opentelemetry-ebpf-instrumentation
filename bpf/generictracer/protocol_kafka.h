// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/large_buffers.h>
#include <common/http_types.h>
#include <common/pin_internal.h>
#include <common/ringbuf.h>
#include <common/runtime.h>
#include <common/tp_info.h>
#include <common/trace_common.h>

#include <generictracer/protocol_common.h>
#include <generictracer/k_tracer_tailcall.h>

#include <generictracer/maps/protocol_cache.h>

#include <maps/active_ssl_connections.h>

// message_size -> https://kafka.apache.org/protocol#protocol_common
// The message_size field in the Kafka protocol defines the size of the
// request/response payload excluding the 4 bytes used by the message_size field itself.

// Every kafka api packet is prefixed by an header
// https://kafka.apache.org/protocol#protocol_messages
struct kafka_request_hdr {
    s32 message_size;
    s16 request_api_key;     // The API key of this request
    s16 request_api_version; // The API version of this request
    s32 correlation_id;      // The correlation ID of this request
    // client-id is a nullable string

    // Metadata
    bool request_hdr_arrived;
    // Signals whether to skip or not the first 4 bytes in the current buffer as
    // they arrived in a previous packet.
    u8 _pad[3];
};

struct kafka_response_hdr {
    s32 message_size;
    s32 correlation_id; // The correlation ID of this response

    // Metadata
    bool response_hdr_arrived;
    // Signals whether to skip or not the first 4 bytes in the current buffer as
    // they arrived in a previous packet.
    u8 _pad[3];
};

struct kafka_state_data {
    s32 message_size;
};

struct kafka_state_key {
    connection_info_t conn;
    u8 packet_type;
    u8 _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, struct kafka_state_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} kafka_state SEC(".maps");

enum {
    k_kafka_hdr_message_size = 4,
    k_kafka_hdr_request_api_key = 2,
    k_kafka_hdr_request_api_version = 2,
    k_kafka_hdr_correlation_id = 4,
    k_kafka_tagged_fields = 1,

    k_kafka_request_hdr_size =
        12, // message_size (4), request_api_key (2), request_api_version(2), correlation_id(4)
    k_kafka_request_hdr_size_without_message_size = 8,

    k_kafka_request_hdr_size_full = k_kafka_request_hdr_size + k_kafka_tagged_fields, // kafka > 2.7
    k_kafka_response_hdr_size = 8,

    k_kafka_response_hdr_size_without_message_size = 4,
    k_kafka_response_hdr_size_full =
        k_kafka_response_hdr_size + k_kafka_tagged_fields, // kafka > 2.7

    // do we need to consider the _tagged_fields (1)??
    k_kafka_min_request_message_size_value =
        10, // request_api_key (2) + request_api_version (2) + correlation_id (4) + client_id (NULLABLE_STRING 2)
    k_kafka_min_response_message_size_value = 4, //  correlation_id (4)

    // Api Keys
    // pino: define all api keys
    // https://kafka.apache.org/protocol#protocol_api_keys
    k_kafka_api_key_produce = 0,
    k_kafka_api_key_fetch = 1,
    k_kafka_api_key_list_offsets = 2,
    k_kafka_api_key_metadata = 3,
    k_kafka_api_key_offset_commit = 8,
    k_kafka_api_key_offsetfetch = 9,
    k_kafka_api_key_find_coordinator = 10,
    k_kafka_api_key_join_group = 11,
    k_kafka_api_key_heartbeat = 12,

    // Sanity checks
    k_kafka_message_size_max = 1 << 13, // 8K
};

// Structure to define the min/max supported versions for an API key
typedef struct {
    s16 api_key;
    s16 min_version;
    s16 max_version;
} kafka_api_version_info_t;

// The size of the lookup_table is the highest API key that we support
#define MAX_KAFKA_API_KEY k_kafka_api_key_metadata

static const kafka_api_version_info_t API_VERSION_LOOKUP_TABLE[MAX_KAFKA_API_KEY + 1] = {
    /* 0 (PRODUCE) */ {.api_key = 0, .min_version = 3, .max_version = 13},
    /* 1 (FETCH)   */ {.api_key = 1, .min_version = 4, .max_version = 18},
    /* 2 (LIST_OFFSETS) */ {.api_key = 2, .min_version = 1, .max_version = 10},
    /* 3 (METADATA)*/ {.api_key = 3, .min_version = 0, .max_version = 13},
    // add more
};

bool is_api_version_supported(s16 api_key, s16 api_version) {
    if (api_key < 0 || api_key > MAX_KAFKA_API_KEY) {
        return false; // API Key is out of the supported range
    }
    // use the lookup table to perform the required check
    const kafka_api_version_info_t *info = &API_VERSION_LOOKUP_TABLE[api_key];

    if (api_version >= info->min_version && api_version <= info->max_version) {
        return true;
    }

    return false;
}

static __always_inline int
read_kafka_message_size(const unsigned char *data, size_t data_len, u8 packet_type) {
    if (data_len < k_kafka_hdr_message_size) {
        return -1;
    }

    int message_size = 0;

    if (packet_type == PACKET_TYPE_REQUEST) {
        bpf_dbg_printk("read_kafka_message_size PACKET_TYPE_REQUEST");
        bpf_probe_read(&message_size, k_kafka_hdr_message_size, (const void *)data);
        message_size = bpf_ntohl(message_size);
        if (message_size < k_kafka_min_request_message_size_value ||
            message_size > k_kafka_message_size_max) {
            bpf_dbg_printk("read_kafka_message_size: invalid request message_size: %d",
                           message_size);
            return -1;
        }
    } else {
        bpf_dbg_printk("read_kafka_message_size PACKET_TYPE_RESPONSE");
        bpf_probe_read(&message_size, k_kafka_hdr_message_size, (const void *)data);
        message_size = bpf_ntohl(message_size);
        if (message_size < k_kafka_min_response_message_size_value ||
            message_size > k_kafka_message_size_max) {
            bpf_dbg_printk("read_kafka_message_size: invalid response message_size: %d",
                           message_size);
            return -1;
        }
    }

    bpf_dbg_printk("read_kafka_message_size: message_size: %d", message_size);
    return message_size;
}

static __always_inline int kafka_store_state_data(const connection_info_t *conn_info,
                                                  const unsigned char *data,
                                                  size_t data_len,
                                                  u8 packet_type) {
    bpf_dbg_printk("====== kafka_store_state_data packet_type %d =======", packet_type);

    // we want to store only request/response of split sends that are 4 bytes long
    if (data_len != k_kafka_hdr_message_size) {
        return 0;
    }

    int message_size = read_kafka_message_size(data, data_len, packet_type);
    if (message_size == -1) {
        return 0;
    }
    struct kafka_state_data new_state_data = {};
    new_state_data.message_size = message_size;
    struct kafka_state_key state_key = {.conn = *conn_info, .packet_type = packet_type};
    bpf_map_update_elem(&kafka_state, &state_key, &new_state_data, BPF_ANY);
    return -1;
}

static __always_inline int kafka_parse_fixup_request_header(const connection_info_t *conn_info,
                                                            struct kafka_request_hdr *hdr,
                                                            const unsigned char *data,
                                                            size_t data_len) {
    bpf_dbg_printk("====== kafka_parse_fixup_request_header =======");

    // Try to parse and validate the header first.
    bpf_probe_read(hdr, k_kafka_request_hdr_size_full, (const void *)data);
    if (hdr->message_size == (data_len - k_kafka_request_hdr_size_full)) {
        // Header is valid and we have the full data, we can proceed.
        hdr->request_hdr_arrived = false;
        return 0;
    }

    // Prepend the header from state data.
    struct kafka_state_key state_key = {.conn = *conn_info, .packet_type = PACKET_TYPE_REQUEST};
    struct kafka_state_data *state_data = bpf_map_lookup_elem(&kafka_state, &state_key);
    if (state_data != NULL) {
        __builtin_memcpy(hdr, state_data, k_kafka_hdr_message_size);
        bpf_probe_read(&hdr->request_api_key, k_kafka_hdr_request_api_key, (const void *)data);
        hdr->request_api_key = bpf_ntohs(hdr->request_api_key);
        if (hdr->request_api_key !=
            k_kafka_api_key_metadata) { // right now we are interested only in metadata
            bpf_dbg_printk(
                "kafka_parse_fixup_request_header: api_request_key provided %d, is not metadata %d",
                hdr->request_api_key,
                k_kafka_api_key_metadata);
            return 0;
        }
        bpf_probe_read(&hdr->request_api_version,
                       k_kafka_hdr_request_api_version,
                       (const void *)data + k_kafka_hdr_request_api_key);
        if (!is_api_version_supported(hdr->request_api_key, hdr->request_api_version)) {
            bpf_dbg_printk("kafka_parse_fixup_request_header: api_version %d not supported for the "
                           "provided api_key %d ",
                           hdr->request_api_version,
                           hdr->request_api_key);
            return 0;
        }
        bpf_probe_read(&hdr->correlation_id,
                       k_kafka_hdr_correlation_id,
                       (const void *)data + k_kafka_hdr_request_api_key +
                           k_kafka_hdr_request_api_version);
        hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
        if (hdr->correlation_id < 0) {
            bpf_dbg_printk("kafka_parse_fixup_request_header: invalid correlation_id: %d",
                           hdr->correlation_id);
            return 0;
        }
        hdr->request_hdr_arrived = true;
        bpf_dbg_printk("kafka_parse_fixup_request_header: good api_request_key %d, "
                       "api_request_version %d, correlation_id %d",
                       hdr->request_api_key,
                       hdr->request_api_version,
                       hdr->correlation_id);
        return 0;
    }

    bpf_dbg_printk("kafka_parse_fixup_request_header: failed to parse kafka request header");
    return -1;
}

static __always_inline int kafka_parse_fixup_response_header(const connection_info_t *conn_info,
                                                             struct kafka_response_hdr *hdr,
                                                             const unsigned char *data,
                                                             size_t data_len) {
    bpf_dbg_printk("====== kafka_parse_fixup_response_header =======");

    // Try to parse and validate the header first.
    bpf_probe_read(hdr, k_kafka_response_hdr_size_full, (const void *)data);
    if (hdr->message_size == (data_len - k_kafka_response_hdr_size_full)) {
        // Header is valid and we have the full data, we can proceed.
        hdr->response_hdr_arrived = false;
        return 0;
    }

    // Prepend the header from state data.
    struct kafka_state_key state_key = {.conn = *conn_info, .packet_type = PACKET_TYPE_RESPONSE};
    struct kafka_state_data *state_data = bpf_map_lookup_elem(&kafka_state, &state_key);
    if (state_data != NULL) {
        __builtin_memcpy(hdr, state_data, k_kafka_hdr_message_size);
        bpf_probe_read(&hdr->correlation_id, k_kafka_hdr_correlation_id, (const void *)data);
        hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
        if (hdr->correlation_id < 0) {
            bpf_dbg_printk("kafka_parse_fixup_response_header: invalid correlation_id: %d",
                           hdr->correlation_id);
            return 0;
        }
        hdr->response_hdr_arrived = true;
        bpf_dbg_printk("kafka_parse_fixup_response_header: good correlation_id %d",
                       hdr->correlation_id);
        return 0;
    }

    bpf_dbg_printk("kafka_parse_fixup_response_header: failed to parse kafka response header");
    return -1;
}

static __always_inline int kafka_read_fixup_buffer(const connection_info_t *conn_info,
                                                   unsigned char *buf,
                                                   u32 *buf_len,
                                                   const unsigned char *data,
                                                   u32 data_len,
                                                   u8 packet_type) {
    bpf_dbg_printk("====== kafka_read_fixup_buffer =======");

    u8 offset = 0;

    struct kafka_state_key state_key = {.conn = *conn_info, .packet_type = packet_type};
    struct kafka_state_data *state_data = bpf_map_lookup_elem(&kafka_state, &state_key);
    if (packet_type == PACKET_TYPE_REQUEST) {
        if (state_data != NULL) {
            bpf_probe_read(
                buf, k_kafka_request_hdr_size_without_message_size, (const void *)state_data);
            offset += k_kafka_request_hdr_size_without_message_size;
            bpf_map_delete_elem(&kafka_state, conn_info);
        } else {
            if (data_len < k_kafka_request_hdr_size) {
                bpf_dbg_printk("kafka_read_fixup_buffer: request data_len is too short: %d",
                               data_len);
                return -1;
            }
        }
    } else {
        if (state_data != NULL) {
            bpf_probe_read(
                buf, k_kafka_response_hdr_size_without_message_size, (const void *)state_data);
            offset += k_kafka_response_hdr_size_without_message_size;
            bpf_map_delete_elem(&kafka_state, conn_info);
        } else {
            if (data_len < k_kafka_response_hdr_size) {
                bpf_dbg_printk("kafka_read_fixup_buffer: response data_len is too short: %d",
                               data_len);
                return -1;
            }
        }
    }
    *buf_len = data_len + offset;
    if (*buf_len >= mysql_buffer_size) {
        *buf_len = mysql_buffer_size;
        bpf_dbg_printk("WARN: kafka_read_fixup_buffer: buffer is full, truncating data");
    }

    bpf_probe_read(buf + offset, *buf_len & k_large_buf_payload_max_size_mask, (const void *)data);

    return *buf_len;
}

static __always_inline int kafka_send_large_buffer(tcp_req_t *req,
                                                   pid_connection_info_t *pid_conn,
                                                   const void *u_buf,
                                                   u32 bytes_len,
                                                   u8 packet_type,
                                                   u8 direction,
                                                   enum large_buf_action action) {
    bpf_dbg_printk("====== kafka_send_large_buffer =======");

    if (kafka_store_state_data(&pid_conn->conn, u_buf, bytes_len, packet_type) < 0) {
        bpf_dbg_printk("kafka_send_large_buffer: 4 bytes packet, storing state data");
        return -1;
    }
    if (packet_type == PACKET_TYPE_RESPONSE) {
        tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)kafka_large_buffers_mem();
        if (!large_buf) {
            bpf_dbg_printk(
                "kafka_send_large_buffer: failed to reserve space for Kafka large buffer");
            return 0;
        }

        large_buf->type = EVENT_TCP_LARGE_BUFFER;
        large_buf->packet_type = packet_type;
        large_buf->action = action;
        large_buf->direction = direction;
        large_buf->conn_info = pid_conn->conn;
        large_buf->tp = req->tp;

        int written = kafka_read_fixup_buffer(
            &pid_conn->conn, large_buf->buf, &large_buf->len, u_buf, bytes_len, packet_type);
        if (written < 0) {
            bpf_dbg_printk(
                "kafka_send_large_buffer: failed to read buffer, not sending large buffer");
            return 0;
        }

        u32 total_size = sizeof(tcp_large_buffer_t);
        total_size += written > sizeof(void *) ? written : sizeof(void *);

        req->has_large_buffers = true;
        bpf_ringbuf_output(&events, large_buf, total_size & k_large_buf_max_size_mask, get_flags());
        return 0;
    }
    return 0;
}

static __always_inline u8 is_kafka(connection_info_t *conn_info,
                                   const unsigned char *data,
                                   u32 data_len,
                                   enum protocol_type *protocol_type,
                                   u8 packet_type) {
    bpf_dbg_printk("====== is_kafka =======");
    if (*protocol_type != k_protocol_type_kafka && *protocol_type != k_protocol_type_unknown) {
        // Already classified, not kafka.
        return 0;
    }

    if (kafka_store_state_data(conn_info, data, (size_t)data_len, packet_type) < 0) {
        bpf_dbg_printk("is_kafka: 4 bytes packet, storing state data");
        return 0;
    }

    struct kafka_request_hdr req_hdr = {};
    struct kafka_response_hdr res_hdr = {};
    if (packet_type == PACKET_TYPE_REQUEST) {
        bpf_dbg_printk("====== is_kafka PACKET_TYPE_REQUEST =======");

        if (kafka_parse_fixup_request_header(conn_info, &req_hdr, data, data_len) != 0) {
            bpf_dbg_printk("is_kafka: failed to parse kafka request header");
            return 0;
        }
        if (req_hdr.message_size > k_kafka_message_size_max) {
            bpf_dbg_printk("is_kafka: request message size is too large: %d", req_hdr.message_size);
            return 0;
        }

        bpf_dbg_printk("is_kafka: kafka! correlation_id=%d", req_hdr.correlation_id);
    } else {
        bpf_dbg_printk("====== is_kafka PACKET_TYPE_RESPONSE =======");

        if (kafka_parse_fixup_response_header(conn_info, &res_hdr, data, data_len) != 0) {
            bpf_dbg_printk("is_kafka: failed to parse kafka response header");
            return 0;
        }
        if (res_hdr.message_size > k_kafka_message_size_max) {
            bpf_dbg_printk("is_kafka: response message size is too large: %d",
                           res_hdr.message_size);
            return 0;
        }

        bpf_dbg_printk("is_kafka: kafka! correlation_id=%d", res_hdr.correlation_id);
    }

    *protocol_type = k_protocol_type_kafka;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}