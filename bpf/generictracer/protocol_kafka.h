// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
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
};

struct kafka_response_hdr {
    s32 message_size;
    s32 correlation_id; // The correlation ID of this response
};

typedef struct kafka_state_data {
    s32 message_size;
} kafka_state_data_t;

typedef struct kafka_state_key {
    connection_info_t conn;
    u8 direction;
    u8 _pad[3];
} kafka_state_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, kafka_state_key_t);
    __type(value, kafka_state_data_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} kafka_state SEC(".maps");

typedef struct kafka_correlation_data {
    s32 correlation_id;
} kafka_correlation_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, kafka_correlation_data_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} kafka_ongoing_requests SEC(".maps");

enum {
    k_kafka_hdr_message_size = 4,
    k_kafka_hdr_request_api_key = 2,
    k_kafka_hdr_request_api_version = 2,
    k_kafka_hdr_correlation_id = 4,

    k_kafka_min_response_message_size_value = 4, // correlation_id (4)

    // https://kafka.apache.org/protocol#protocol_api_keys
    k_kafka_api_key_metadata = 3,
    // only versions 10-13 contain topic_id which we are interested in
    k_kafka_min_metadata_api_version = 10,
    k_kafka_max_metadata_api_version = 13,

    // Sanity checks
    k_kafka_message_size_max = 1 << 13, // 8K
};

static __always_inline int kafka_read_message_size(const unsigned char *data, size_t data_len) {
    if (data_len < k_kafka_hdr_message_size) {
        return -1;
    }

    int message_size = 0;
    bpf_probe_read(&message_size, k_kafka_hdr_message_size, (const void *)data);
    message_size = bpf_ntohl(message_size);

    // we can be in the case where we already have the first part
    // of the header saved in the map and we are reading the second
    // part so we think that is message_size but it is actually
    // key+version in case of request or the correlation id in case of
    // response

    if (message_size < k_kafka_min_response_message_size_value ||
        message_size > k_kafka_message_size_max) {
        bpf_dbg_printk("possible invalid message_size: %d", message_size);
        return 0;
    }
    return message_size;
}

// This function is used to store the Kafka header if it comes in split packets
// from double send.
// Given the fact that we need to store this for the duration of the full request
// (split in potentially multiple packets), we will **not** process or preserve
// any actual payloads that are exactly 4 bytes long — they are intentionally
// dropped in favor of state storage.
static __always_inline int kafka_store_state_data(const connection_info_t *conn_info,
                                                  const unsigned char *data,
                                                  size_t data_len,
                                                  u8 direction) {

    // we want to store only request/response of split sends that are 4 bytes long
    if (data_len != k_kafka_hdr_message_size) {
        return 0;
    }

    int message_size = kafka_read_message_size(data, data_len);
    if (message_size == -1) {
        return 0;
    }
    kafka_state_data_t new_state_data = {};
    new_state_data.message_size = message_size;
    kafka_state_key_t state_key = {.conn = *conn_info, .direction = direction};
    bpf_map_update_elem(&kafka_state, &state_key, &new_state_data, BPF_ANY);

    return -1;
}

// This function reads all fields in a request header, ignoring the first field (message_size).
// Specifically, it also checks whether the request_api_key is relevant to us (currently, we're
// only interested in the Metadata type), whether the request_api_version is valid, and whether
// the correlation_id is valid.
// Note: we are interested in request_api_version values ​​between 10 and 13 because
// these versions contain the topic_id while versions < 9 have directly the topic_name.
static __always_inline int
kafka_check_request_header_fields_without_message_size(struct kafka_request_hdr *hdr,
                                                       const unsigned char *data) {

    u8 offset = 0;

    bpf_probe_read(&hdr->request_api_key, k_kafka_hdr_request_api_key, (const void *)(data));
    hdr->request_api_key = bpf_ntohs(hdr->request_api_key);
    if (hdr->request_api_key != k_kafka_api_key_metadata) {
        bpf_dbg_printk("request_api_key "
                       "provided %d, is not metadata(%d)",
                       hdr->request_api_key,
                       k_kafka_api_key_metadata);
        return -1;
    }

    offset += k_kafka_hdr_request_api_key;
    bpf_probe_read(
        &hdr->request_api_version, k_kafka_hdr_request_api_version, (const void *)(data + offset));
    hdr->request_api_version = bpf_ntohs(hdr->request_api_version);
    if (hdr->request_api_version < k_kafka_min_metadata_api_version ||
        hdr->request_api_version > k_kafka_max_metadata_api_version) {
        bpf_dbg_printk("provided "
                       "api_version %d not supported for the provided request_api_key %d ",
                       hdr->request_api_version,
                       hdr->request_api_key);
        return -1;
    }

    offset += k_kafka_hdr_request_api_version;
    bpf_probe_read(&hdr->correlation_id, k_kafka_hdr_correlation_id, (const void *)(data + offset));
    hdr->correlation_id = bpf_ntohl(hdr->correlation_id);

    if (hdr->correlation_id < 0) {
        bpf_dbg_printk("invalid correlation_id: %d", hdr->correlation_id);
        return -1;
    }
    return 0;
}

// Request header
// +--------------+-----------------+---------------------+----------------|
// | message_size | request_api_key | request_api_version | correlation_id |
// +--------------+-----------------+---------------------+----------------|
// |    4B        |     2B          |     2B              |      4B        |
// +--------------+-----------------+---------------------+----------------|
// This function parses the request header. First, it reads the value of the message_size field.
// If the value is equal to the size of the received data minus the size of message_size itself,
// then we've just received data that possibly indicates a healthy packet.
// Otherwise, we need to check if we have a valid message_size saved in the kafka_state map,
// and if the value of message_size is equal to the size of the received data,
// which means we've received the entire packet minus the message_size we already had.
// In both cases, we try to read all the remaining fields and see if it is a intersted and valid packet.
static __always_inline int kafka_parse_fixup_request_header(const connection_info_t *conn_info,
                                                            struct kafka_request_hdr *hdr,
                                                            const unsigned char *data,
                                                            size_t data_len,
                                                            u8 direction) {

    // Try to parse and validate the header first.
    hdr->message_size = kafka_read_message_size(data, data_len);
    if (hdr->message_size == -1) {
        return -1;
    }
    if (hdr->message_size == (data_len - k_kafka_hdr_message_size)) {
        // Header is valid and we have the full data, we can proceed.
        if (kafka_check_request_header_fields_without_message_size(
                hdr, data + k_kafka_hdr_message_size) < 0) {
            return -1;
        }
        return 0;
    }

    kafka_state_key_t state_key = {.conn = *conn_info, .direction = direction};
    kafka_state_data_t *state_data = bpf_map_lookup_elem(&kafka_state, &state_key);
    if (state_data != NULL && state_data->message_size == data_len) {
        // Prepend the header from state data.
        hdr->message_size = state_data->message_size;
        if (kafka_check_request_header_fields_without_message_size(hdr, data) < 0) {
            return -1;
        }
        return 0;
    }

    bpf_dbg_printk("failed to parse kafka request header");
    return -1;
}

// This function reads the response header correlation_id field and checks if it is
// a valid value
static __always_inline int
kafka_check_response_header_correlation_id(struct kafka_response_hdr *hdr,
                                           const unsigned char *data) {

    bpf_probe_read(&hdr->correlation_id, k_kafka_hdr_correlation_id, (const void *)data);
    hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
    if (hdr->correlation_id < 0) {
        bpf_dbg_printk("invalid correlation_id: %d", hdr->correlation_id);
        return -1;
    }
    return 0;
}

// Response header
// +--------------+----------------|
// | message_size | correlation_id |
// +--------------+----------------|
// |    4B        |       4B.      |
// +--------------+----------------|
// This function parses the response header. First, it reads the value of the message_size field.
// If the value is equal to the size of the received data minus the size of message_size itself,
// then we've just received data that possibly indicates a healthy packet.
// Otherwise, we need to check if we have a valid message_size saved in the kafka_state map,
// and if the value of message_size is equal to the size of the received data,
// which means we've received the entire packet minus the message_size we already had.
// In both cases, we need to check if the value of the correlation_id field is valid.
static __always_inline int kafka_parse_fixup_response_header(const connection_info_t *conn_info,
                                                             struct kafka_response_hdr *hdr,
                                                             const unsigned char *data,
                                                             size_t data_len,
                                                             u8 direction) {
    // Try to parse and validate the header first.
    hdr->message_size = kafka_read_message_size(data, data_len);
    if (hdr->message_size == -1) {
        return -1;
    }

    if (hdr->message_size == (data_len - k_kafka_hdr_message_size)) {
        // Header is valid and we have the full data, we can proceed.
        if (kafka_check_response_header_correlation_id(hdr, data + k_kafka_hdr_message_size) < 0) {
            return -1;
        }
        return 0;
    }
    // Prepend the header from state data.
    kafka_state_key_t state_key = {.conn = *conn_info, .direction = direction};
    kafka_state_data_t *state_data = bpf_map_lookup_elem(&kafka_state, &state_key);
    if (state_data != NULL && state_data->message_size == data_len) {
        // Prepend the header from state data.
        hdr->message_size = state_data->message_size;
        if (kafka_check_response_header_correlation_id(hdr, data) < 0) {
            return -1;
        }
        return 0;
    }

    bpf_dbg_printk("failed to parse kafka response header");
    return -1;
}

// This is an alternative version of kafka_parse_fixup_response_header that fills the buffer
// without reading header fields.
// We are interested only in response, that's why the check on the size is done using
// the minimum response header size.
static __always_inline int kafka_read_fixup_response_buffer(const connection_info_t *conn_info,
                                                            unsigned char *buf,
                                                            u32 *buf_len,
                                                            const unsigned char *data,
                                                            u32 data_len,
                                                            u8 direction) {
    u8 offset = 0;

    kafka_state_key_t state_key = {.conn = *conn_info, .direction = direction};
    kafka_state_data_t *state_data = bpf_map_lookup_elem(&kafka_state, &state_key);
    if (state_data != NULL && (state_data->message_size == data_len)) {
        state_data->message_size = bpf_htonl(state_data->message_size);
        bpf_probe_read(buf, k_kafka_hdr_message_size, (const void *)state_data);
        offset += k_kafka_hdr_message_size;
        bpf_map_delete_elem(&kafka_state, &state_key);
    } else {
        if (data_len < k_kafka_min_response_message_size_value) {
            bpf_dbg_printk("response data_len is too short: %d", data_len);
            return -1;
        }
    }

    *buf_len = data_len + offset;
    if (*buf_len >= kafka_buffer_size) {
        *buf_len = kafka_buffer_size;
        bpf_dbg_printk("WARN: buffer is full, truncating data");
    }

    bpf_probe_read(buf + offset, *buf_len & k_large_buf_payload_max_size_mask, (const void *)data);

    return *buf_len;
}

// Emit a large buffer event for Kafka protocol.
// The return value is used to control the flow for this specific protocol.
// -1: wait additional data; 0: continue, regardless of errors.
static __always_inline int kafka_send_large_buffer(tcp_req_t *req,
                                                   pid_connection_info_t *pid_conn,
                                                   const void *u_buf,
                                                   u32 bytes_len,
                                                   u8 direction,
                                                   enum large_buf_action action) {

    if (kafka_store_state_data(&pid_conn->conn, u_buf, bytes_len, direction) < 0) {
        bpf_dbg_printk("4 bytes packet, storing state data");
        return -1;
    }

    // check if this event matches an ongoing request
    kafka_correlation_data_t *correlation_data =
        bpf_map_lookup_elem(&kafka_ongoing_requests, &pid_conn->conn);
    if (!correlation_data) {
        bpf_dbg_printk("no ongoing request found for this response");
        return 0;
    }

    struct kafka_response_hdr hdr = {};
    if (kafka_parse_fixup_response_header(&pid_conn->conn, &hdr, u_buf, bytes_len, direction) !=
        0) {
        bpf_dbg_printk("failed to check kafka response header");
        return 0;
    }

    if (hdr.correlation_id != correlation_data->correlation_id) {
        bpf_dbg_printk("request correlation_id != response "
                       "correlation_id, %d != %d. Ignoring...",
                       correlation_data->correlation_id,
                       hdr.correlation_id);
        return 0;
    }

    bpf_map_delete_elem(&kafka_ongoing_requests, &pid_conn->conn);

    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)kafka_large_buffers_mem();
    if (!large_buf) {
        bpf_dbg_printk("failed to reserve space for Kafka large buffer");
        return 0;
    }

    // If we are here it means that the packet is for sure a good response because
    // we populated the hdr with message_size and correlation_id
    // we checked also in the map of ongoing requests if there was a related
    // ongoing request so we can hardcode the packet_type as response
    // **NOTE**: we only send the response as a large buffer event in userspace
    // because the topic_id and name are in the response.
    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->packet_type = PACKET_TYPE_RESPONSE;

    large_buf->action = action;
    large_buf->direction = direction;
    large_buf->conn_info = pid_conn->conn;
    large_buf->tp = req->tp;

    int written = kafka_read_fixup_response_buffer(
        &pid_conn->conn, large_buf->buf, &large_buf->len, u_buf, bytes_len, direction);
    if (written < 0) {
        bpf_dbg_printk("failed to read buffer, not sending large buffer");
        return 0;
    }

    u32 total_size = sizeof(tcp_large_buffer_t);
    total_size += written > sizeof(void *) ? written : sizeof(void *);

    req->has_large_buffers = true;
    bpf_ringbuf_output(&events, large_buf, total_size & k_large_buf_max_size_mask, get_flags());
    return 0;
}

// This function first checks whether the received event hasn't already been classified as Kafka;
// it then attempts to save the data in a map if and only if it's a 4 byte packet (we're interested
// in the message_size field). If the event is of interest to us, we try to parse it as if it were
// a request, because the sequence of bytes that characterizes a request is better than a response;
// if that fails, we try parsing it as a response.
// If we find a request, we save it in an ongoing request map.
// If we find a response (or at least something that looks like a response from the bytes),
// we need to perform a further check: see if we have an ongoing request related to this response
// using the correlation_id.
// In both cases, if we found a Kafka packet, we update the protocol_cache map and return.
static __always_inline u8 is_kafka(connection_info_t *conn_info,
                                   const unsigned char *data,
                                   u32 data_len,
                                   enum protocol_type *protocol_type,
                                   u8 direction) {
    if (*protocol_type != k_protocol_type_kafka && *protocol_type != k_protocol_type_unknown) {
        // Already classified, not kafka.
        return 0;
    }

    if (kafka_store_state_data(conn_info, data, (size_t)data_len, direction) < 0) {
        bpf_dbg_printk("4 bytes packet, storing state data");
        return 0;
    }

    struct kafka_request_hdr req_hdr = {};
    struct kafka_response_hdr res_hdr = {};
    if (kafka_parse_fixup_request_header(conn_info, &req_hdr, data, data_len, direction) == 0) {
        kafka_correlation_data_t correlation_data = {};
        correlation_data.correlation_id = req_hdr.correlation_id;
        bpf_map_update_elem(&kafka_ongoing_requests, conn_info, &correlation_data, BPF_ANY);
        bpf_dbg_printk("kafka! request_api_key %d, correlation_id=%d",
                       req_hdr.request_api_key,
                       req_hdr.correlation_id);
    } else {
        if (kafka_parse_fixup_response_header(conn_info, &res_hdr, data, data_len, direction) !=
            0) {
            bpf_dbg_printk("failed to parse kafka response header");
            return 0;
        }

        kafka_correlation_data_t *correlation_data =
            bpf_map_lookup_elem(&kafka_ongoing_requests, conn_info);
        if (!correlation_data) {
            bpf_dbg_printk("no ongoing request found for this response");
            return 0;
        }

        if (res_hdr.correlation_id != correlation_data->correlation_id) {
            bpf_dbg_printk("request correlation_id != response "
                           "correlation_id, %d != %d. Ignoring...",
                           correlation_data->correlation_id,
                           res_hdr.correlation_id);
            return 0;
        }

        bpf_dbg_printk("kafka! message_size %d, correlation_id=%d",
                       res_hdr.message_size,
                       res_hdr.correlation_id);
    }
    *protocol_type = k_protocol_type_kafka;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}