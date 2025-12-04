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
};

struct kafka_response_hdr {
    s32 message_size;
    s32 correlation_id; // The correlation ID of this response
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

struct kafka_correlation_data {
    s32 correlation_id;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, struct kafka_correlation_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} kafka_ongoing_requests SEC(".maps");

enum {
    k_kafka_hdr_message_size = 4,
    k_kafka_hdr_request_api_key = 2,
    k_kafka_hdr_request_api_version = 2,
    k_kafka_hdr_correlation_id = 4,

    // do we need to consider the _tagged_fields (1)??
    k_kafka_min_request_message_size_value =
        10, // request_api_key (2) + request_api_version (2) + correlation_id (4) + client_id (NULLABLE_STRING 2)
    k_kafka_min_response_message_size_value = 4, //  correlation_id (4)

    // https://kafka.apache.org/protocol#protocol_api_keys
    k_kafka_api_key_metadata = 3,

    // Sanity checks
    k_kafka_message_size_max = 1 << 13, // 8K
};

// Structure to define the min/max supported versions for an API key
typedef struct {
    s16 api_key;
    s16 min_version;
    s16 max_version;
} kafka_api_version_info_t;

static const kafka_api_version_info_t API_VERSION_LOOKUP_TABLE[1] = {
    /* 3 (METADATA)*/ {.api_key = 3, .min_version = 0, .max_version = 13},
};

bool is_api_version_supported(s16 api_key, s16 api_version) {
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
    bpf_probe_read(&message_size, k_kafka_hdr_message_size, (const void *)data);
    message_size = bpf_ntohl(message_size);
    bpf_dbg_printk(
        "read_kafka_message_size packet_type %d, message_size %d", packet_type, message_size);

    if (packet_type == PACKET_TYPE_REQUEST) {
        bpf_dbg_printk("read_kafka_message_size PACKET_TYPE_REQUEST");
        if (message_size < k_kafka_min_request_message_size_value ||
            message_size > k_kafka_message_size_max) {
            bpf_dbg_printk("read_kafka_message_size: invalid request message_size: %d",
                           message_size);
            return -1;
        }
    } else {
        bpf_dbg_printk("read_kafka_message_size PACKET_TYPE_RESPONSE");
        if (message_size < k_kafka_min_response_message_size_value ||
            message_size > k_kafka_message_size_max) {
            bpf_dbg_printk("read_kafka_message_size: invalid response message_size: %d",
                           message_size);
            return -1;
        }
    }

    bpf_dbg_printk(
        "read_kafka_message_size: message_size: %d, packet_type %d", message_size, packet_type);
    return message_size;
}

static __always_inline int kafka_store_state_data(const connection_info_t *conn_info,
                                                  const unsigned char *data,
                                                  size_t data_len,
                                                  u8 packet_type) {
    bpf_dbg_printk(
        "====== kafka_store_state_data packet_type %d, data_len %d =======", packet_type, data_len);

    // we want to store only request/response of split sends that are 4 bytes long
    if (data_len != k_kafka_hdr_message_size) {
        bpf_dbg_printk("====== return kafka_store_state_data packet_type %d =======", packet_type);
        return 0;
    }

    int message_size = read_kafka_message_size(data, data_len, packet_type);
    if (message_size == -1) {
        return 0;
    }
    struct kafka_state_data new_state_data = {};
    new_state_data.message_size = message_size;
    struct kafka_state_key state_key = {.conn = *conn_info, .packet_type = packet_type};
    if (bpf_map_update_elem(&kafka_state, &state_key, &new_state_data, BPF_ANY) < 0) {
        bpf_dbg_printk("====== kafka_store_state_data  bpf_map_update_elem error =======");
    }
    return -1;
}

static __always_inline int kafka_parse_fixup_request_header(const connection_info_t *conn_info,
                                                            struct kafka_request_hdr *hdr,
                                                            const unsigned char *data,
                                                            size_t data_len) {
    bpf_dbg_printk("====== kafka_parse_fixup_request_header data_len %d =======", data_len);
    bpf_dbg_printk("====== kafka_parse_fixup_request_header data %llu =======",
                   (unsigned long long)(uintptr_t)data);

    // Try to parse and validate the header first.
    bpf_probe_read(&hdr->message_size, k_kafka_hdr_message_size, (const void *)data);
    hdr->message_size = bpf_ntohl(hdr->message_size);

    if (hdr->message_size == (data_len - k_kafka_hdr_message_size)) {
        bpf_dbg_printk("====== kafka_parse_fixup_request_header hdr->message_size %d =======",
                       hdr->message_size);
        bpf_dbg_printk("====== kafka_parse_fixup_request_header full data =======");
        unsigned char tmp[12];
        bpf_probe_read(&tmp, 12, &data);
        bpf_dbg_printk("====== kafka_parse_fixup_request_header data %llu =======",
                       (unsigned long long)(uintptr_t)data);
        bpf_dbg_printk("tmp kafka_parse_fixup_request_header message_size: %d %d %d %d",
                       tmp[0],
                       tmp[1],
                       tmp[2],
                       tmp[3]);
        bpf_dbg_printk(
            "tmp kafka_parse_fixup_request_header request_api_key: %d %d", tmp[4], tmp[5]);
        bpf_dbg_printk(
            "tmp kafka_parse_fixup_request_header request_api_version: %d %d", tmp[6], tmp[7]);
        bpf_dbg_printk("tmp kafka_parse_fixup_request_header correlation_id: %d %d %d %d",
                       tmp[8],
                       tmp[9],
                       tmp[10],
                       tmp[11]);
        struct kafka_request_hdr help = {};
        bpf_probe_read(&help, 12, &data);
        bpf_dbg_printk("====== kafka_parse_fixup_request_header data %llu =======",
                       (unsigned long long)(uintptr_t)data);
        bpf_dbg_printk("help kafka_parse_fixup_request_header message_size: %d",
                       bpf_ntohl(help.message_size));
        bpf_dbg_printk("help kafka_parse_fixup_request_header request_api_key: %d",
                       bpf_ntohs(help.request_api_key));
        bpf_dbg_printk("help kafka_parse_fixup_request_header request_api_version: %d",
                       bpf_ntohs(help.request_api_version));
        bpf_dbg_printk("help kafka_parse_fixup_request_header correlation_id: %d",
                       bpf_ntohl(help.correlation_id));
        // Header is valid and we have the full data, we can proceed.
        bpf_dbg_printk(
            "====== kafka_parse_fixup_request_header data+k_kafka_hdr_message_size %llu =======",
            (unsigned long long)(uintptr_t)data + k_kafka_hdr_message_size);
        bpf_probe_read(&hdr->request_api_key,
                       k_kafka_hdr_request_api_key,
                       (const void *)(data + k_kafka_hdr_message_size));
        hdr->request_api_key = bpf_ntohs(hdr->request_api_key);
        if (hdr->request_api_key !=
            k_kafka_api_key_metadata) { // right now we are interested only in metadata
            bpf_dbg_printk(
                "kafka_parse_fixup_request_header: api_request_key provided %d, is not metadata %d",
                hdr->request_api_key,
                k_kafka_api_key_metadata);
            return -1;
        }
        bpf_dbg_printk("====== kafka_parse_fixup_request_header data+k_kafka_hdr_message_size + "
                       "k_kafka_hdr_request_api_key %llu =======",
                       (unsigned long long)(uintptr_t)data + k_kafka_hdr_message_size +
                           k_kafka_hdr_request_api_key);
        bpf_probe_read(
            &hdr->request_api_version,
            k_kafka_hdr_request_api_version,
            (const void *)(data + k_kafka_hdr_message_size + k_kafka_hdr_request_api_key));
        hdr->request_api_version = bpf_ntohs(hdr->request_api_version);
        if (!is_api_version_supported(hdr->request_api_key, hdr->request_api_version)) {
            bpf_dbg_printk("kafka_parse_fixup_request_header: api_version %d not supported for the "
                           "provided api_key %d ",
                           hdr->request_api_version,
                           hdr->request_api_key);
            return -1;
        }
        bpf_dbg_printk("====== kafka_parse_fixup_request_header data+k_kafka_hdr_message_size + "
                       "k_kafka_hdr_request_api_key + k_kafka_hdr_request_api_version %llu =======",
                       (unsigned long long)(uintptr_t)data + k_kafka_hdr_message_size +
                           k_kafka_hdr_request_api_key + k_kafka_hdr_request_api_version);
        bpf_probe_read(&hdr->correlation_id,
                       k_kafka_hdr_correlation_id,
                       (const void *)(data + k_kafka_hdr_message_size +
                                      k_kafka_hdr_request_api_key +
                                      k_kafka_hdr_request_api_version));
        hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
        bpf_dbg_printk(
            "====== kafka_parse_fixup_request_header: print all data (data_len %d): message_size: "
            "%d request_api_key %d, request_api_version %d, correlation_id %d",
            data_len,
            hdr->message_size,
            hdr->request_api_key,
            hdr->request_api_version,
            hdr->correlation_id);

        if (hdr->correlation_id < 0) {
            bpf_dbg_printk("kafka_parse_fixup_request_header: invalid correlation_id: %d",
                           hdr->correlation_id);
            return -1;
        }
        bpf_dbg_printk("kafka_parse_fixup_request_header: good api_request_key %d, "
                       "api_request_version %d, correlation_id %d",
                       hdr->request_api_key,
                       hdr->request_api_version,
                       hdr->correlation_id);
        return 0;
    }
    bpf_dbg_printk("====== kafka_parse_fixup_request_header 2 =======");
    // Prepend the header from state data.
    struct kafka_state_key state_key = {.conn = *conn_info, .packet_type = PACKET_TYPE_REQUEST};
    struct kafka_state_data *state_data = bpf_map_lookup_elem(&kafka_state, &state_key);
    if (state_data != NULL && state_data->message_size == data_len - k_kafka_hdr_message_size) {
        unsigned char tmp[8];
        bpf_probe_read(&tmp, 8, &data);
        bpf_dbg_printk(
            "====== 2 kafka_parse_fixup_request_header data (without memssage_size) %llu =======",
            (unsigned long long)(uintptr_t)data);
        bpf_dbg_printk(
            "====== 2 kafka_parse_fixup_request_header request_api_key: %d %d", tmp[0], tmp[1]);
        bpf_dbg_printk(
            "====== 2 kafka_parse_fixup_request_header request_api_version: %d %d", tmp[2], tmp[3]);
        bpf_dbg_printk("====== 2 kafka_parse_fixup_request_header correlation_id: %d %d %d %d",
                       tmp[4],
                       tmp[5],
                       tmp[6],
                       tmp[7]);
        //__builtin_memcpy(hdr, state_data, k_kafka_hdr_message_size);
        hdr->message_size = state_data->message_size;
        bpf_probe_read(&hdr->request_api_key, k_kafka_hdr_request_api_key, (const void *)data);
        hdr->request_api_key = bpf_ntohs(hdr->request_api_key);
        bpf_dbg_printk("====== 2 kafka_parse_fixup_request_header hdr->message_size %d =======",
                       hdr->message_size);
        bpf_dbg_printk("====== 2 kafka_parse_fixup_request_header hdr->request_api_key %d =======",
                       hdr->request_api_key);
        if (hdr->request_api_key !=
            k_kafka_api_key_metadata) { // right now we are interested only in metadata
            bpf_dbg_printk(
                "kafka_parse_fixup_request_header: api_request_key provided %d, is not metadata %d",
                hdr->request_api_key,
                k_kafka_api_key_metadata);
            return -1;
        }
        bpf_dbg_printk("====== 2 kafka_parse_fixup_request_header data + "
                       "k_kafka_hdr_request_api_key (without memssage_size) %llu =======",
                       (unsigned long long)(uintptr_t)data + k_kafka_hdr_request_api_key);

        bpf_probe_read(&hdr->request_api_version,
                       k_kafka_hdr_request_api_version,
                       (const void *)(data + k_kafka_hdr_request_api_key));
        hdr->request_api_version = bpf_ntohs(hdr->request_api_version);
        if (!is_api_version_supported(hdr->request_api_key, hdr->request_api_version)) {
            bpf_dbg_printk("kafka_parse_fixup_request_header: api_version %d not supported for the "
                           "provided api_key %d ",
                           hdr->request_api_version,
                           hdr->request_api_key);
            return -1;
        }
        bpf_dbg_printk(
            "====== 2 kafka_parse_fixup_request_header data + k_kafka_hdr_request_api_key + "
            "k_kafka_hdr_request_api_version (without memssage_size) %llu =======",
            (unsigned long long)(uintptr_t)data + k_kafka_hdr_request_api_key +
                k_kafka_hdr_request_api_version);

        bpf_probe_read(
            &hdr->correlation_id,
            k_kafka_hdr_correlation_id,
            (const void *)(data + k_kafka_hdr_request_api_key + k_kafka_hdr_request_api_version));
        hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
        bpf_dbg_printk(
            "====== 2 kafka_parse_fixup_request_header: print all data (data_len %d): "
            "message_size: %d request_api_key %d, request_api_version %d, correlation_id %d",
            data_len,
            hdr->message_size,
            hdr->request_api_key,
            hdr->request_api_version,
            hdr->correlation_id);

        if (hdr->correlation_id < 0) {
            bpf_dbg_printk("kafka_parse_fixup_request_header: invalid correlation_id: %d",
                           hdr->correlation_id);
            return -1;
        }
        //hdr->request_hdr_arrived = true;
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
    bpf_dbg_printk("====== kafka_parse_fixup_response_header data_len %d =======", data_len);
    bpf_dbg_printk("====== kafka_parse_fixup_response_header data %llu =======",
                   (unsigned long long)(uintptr_t)data);

    // Try to parse and validate the header first.
    bpf_probe_read(&hdr->message_size, k_kafka_hdr_message_size, (const void *)data);
    hdr->message_size = bpf_ntohl(hdr->message_size);
    if (hdr->message_size == (data_len - k_kafka_hdr_message_size)) {
        unsigned char tmp[8];
        bpf_probe_read(&tmp, 8, &data);
        bpf_dbg_printk("====== kafka_parse_fixup_response_header data %llu =======",
                       (unsigned long long)(uintptr_t)data);
        bpf_dbg_printk("====== kafka_parse_fixup_response_header message_size: %d %d %d %d",
                       tmp[0],
                       tmp[1],
                       tmp[2],
                       tmp[3]);
        bpf_dbg_printk("====== kafka_parse_fixup_response_header correlation_id: %d %d %d %d",
                       tmp[4],
                       tmp[5],
                       tmp[6],
                       tmp[7]);
        bpf_dbg_printk("====== kafka_parse_fixup_response_header hdr->message_size %d =======",
                       hdr->message_size);
        bpf_dbg_printk("====== kafka_parse_fixup_response_header  full data =======");
        // Header is valid and we have the full data, we can proceed.
        bpf_dbg_printk(
            "====== kafka_parse_fixup_response_header data+k_kafka_hdr_message_size %llu =======",
            (unsigned long long)(uintptr_t)data + k_kafka_hdr_message_size);
        bpf_probe_read(&hdr->correlation_id,
                       k_kafka_hdr_correlation_id,
                       (const void *)(data + k_kafka_hdr_message_size));
        hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
        bpf_dbg_printk("====== kafka_parse_fixup_response_header: print all data (data_len %d): "
                       "message_size: %d, correlation_id %d",
                       data_len,
                       hdr->message_size,
                       hdr->correlation_id);

        if (hdr->correlation_id < 0) {
            bpf_dbg_printk("kafka_parse_fixup_response_header: invalid correlation_id: %d",
                           hdr->correlation_id);
            return -1;
        }
        //hdr->response_hdr_arrived = true;
        bpf_dbg_printk("kafka_parse_fixup_response_header: good correlation_id %d",
                       hdr->correlation_id);
        return 0;
    }

    // Prepend the header from state data.
    struct kafka_state_key state_key = {.conn = *conn_info, .packet_type = PACKET_TYPE_RESPONSE};
    struct kafka_state_data *state_data = bpf_map_lookup_elem(&kafka_state, &state_key);
    if (state_data != NULL && state_data->message_size == data_len - k_kafka_hdr_message_size) {
        unsigned char tmp[4];
        bpf_probe_read(&tmp, 4, &data);
        bpf_dbg_printk(
            "====== 2 kafka_parse_fixup_response_header data (without memssage_size) %llu =======",
            (unsigned long long)(uintptr_t)data);
        bpf_dbg_printk("====== 2 kafka_parse_fixup_response_header correlation_id: %d %d %d %d",
                       tmp[0],
                       tmp[1],
                       tmp[2],
                       tmp[3]);
        //__builtin_memcpy(hdr, state_data, k_kafka_hdr_message_size);
        hdr->message_size = state_data->message_size;
        bpf_probe_read(&hdr->correlation_id, k_kafka_hdr_correlation_id, (const void *)data);
        hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
        bpf_dbg_printk("====== 2 kafka_parse_fixup_response_header hdr->message_size %d =======",
                       hdr->message_size);
        bpf_dbg_printk("====== 2 kafka_parse_fixup_response_header hdr->correlation_id %d =======",
                       hdr->correlation_id);
        bpf_dbg_printk("====== 2 kafka_parse_fixup_response_header: print all data (data_len %d): "
                       "message_size: %d, correlation_id %d",
                       data_len,
                       hdr->message_size,
                       hdr->correlation_id);

        if (hdr->correlation_id < 0) {
            bpf_dbg_printk("kafka_parse_fixup_response_header: invalid correlation_id: %d",
                           hdr->correlation_id);
            return -1;
        }
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
    if (state_data != NULL) {
        bpf_probe_read(buf, k_kafka_hdr_message_size, (const void *)state_data);
        offset += k_kafka_hdr_message_size;
        bpf_map_delete_elem(&kafka_state, conn_info);
    } else {
        if (packet_type == PACKET_TYPE_REQUEST &&
            data_len < k_kafka_min_request_message_size_value) {
            bpf_dbg_printk("kafka_read_fixup_buffer: request data_len is too short: %d", data_len);
            return -1;
        } else if (packet_type == PACKET_TYPE_RESPONSE &&
                   data_len < k_kafka_min_response_message_size_value) {
            bpf_dbg_printk("kafka_read_fixup_buffer: response data_len is too short: %d", data_len);
            return -1;
        }
    }
    *buf_len = data_len + offset;
    if (*buf_len >= kafka_buffer_size) {
        *buf_len = kafka_buffer_size;
        bpf_dbg_printk("WARN: kafka_read_fixup_buffer: buffer is full, truncating data");
    }

    bpf_probe_read(buf + offset, *buf_len & k_large_buf_payload_max_size_mask, (const void *)data);

    return *buf_len;
}

static __always_inline u32 check_kafka_response_header(const unsigned char *data,
                                                       size_t data_len,
                                                       struct kafka_response_hdr *hdr) {
    if (data_len < k_kafka_min_response_message_size_value) {
        bpf_dbg_printk("check_kafka_response_header: data_len too low: %d", data_len);
        return 0;
    }

    bpf_probe_read((void *)&hdr->message_size, k_kafka_hdr_message_size, (const void *)data);
    hdr->message_size = bpf_ntohl(hdr->message_size);
    if (hdr->message_size < k_kafka_min_response_message_size_value ||
        hdr->message_size > k_kafka_message_size_max) {
        bpf_dbg_printk("check_kafka_response_header: invalid message_size %d", hdr->message_size);
        return 0;
    }
    bpf_probe_read(&hdr->correlation_id, sizeof(hdr->correlation_id), (const void *)(data + 4));
    hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
    if (hdr->correlation_id < 0) {
        bpf_dbg_printk("check_kafka_response_header: invalid correlation_id: %d",
                       hdr->correlation_id);
        return 0;
    }

    return 1;
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
        // check if this response matches an ongoing request
        struct kafka_correlation_data *correlation_data =
            bpf_map_lookup_elem(&kafka_ongoing_requests, &pid_conn->conn);
        if (!correlation_data) {
            bpf_dbg_printk("kafka_send_large_buffer: no ongoing request found for this response");
            return 0;
        }
        struct kafka_response_hdr hdr = {};
        if (check_kafka_response_header(u_buf, bytes_len, &hdr) == 0) {
            bpf_dbg_printk("kafka_send_large_buffer: failed to check kafka response header");
            return 0;
        }
        if (hdr.correlation_id != correlation_data->correlation_id) {
            bpf_dbg_printk("kafka_send_large_buffer: request correlation_id != response "
                           "correlation_id, %d != %d",
                           correlation_data->correlation_id,
                           hdr.correlation_id);
            return 0;
        }
        bpf_map_delete_elem(&kafka_ongoing_requests, &pid_conn->conn);

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

        bpf_dbg_printk(
            "kafka_send_large_buffer: sent large buffer packet_type %d, correlation_id %d",
            packet_type,
            hdr.correlation_id);
        return 0;
    }
    bpf_dbg_printk("kafka_send_large_buffer: is a request, not sending large buffer");
    return -1;
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
        bpf_dbg_printk("====== is_kafka PACKET_TYPE_REQUEST ======= %d", packet_type);

        if (kafka_parse_fixup_request_header(conn_info, &req_hdr, data, data_len) != 0) {
            bpf_dbg_printk("is_kafka: failed to parse kafka request header");
            return 0;
        }
        if (req_hdr.message_size > k_kafka_message_size_max) {
            bpf_dbg_printk("is_kafka: request message size is too large: %d", req_hdr.message_size);
            return 0;
        }
        struct kafka_correlation_data correlation_data = {};
        correlation_data.correlation_id = req_hdr.correlation_id;
        bpf_map_update_elem(&kafka_ongoing_requests, conn_info, &correlation_data, BPF_ANY);
        bpf_dbg_printk("is_kafka: kafka! message_size %d, request_api_key %d, request_api_version "
                       "%d, correlation_id=%d",
                       req_hdr.message_size,
                       req_hdr.request_api_key,
                       req_hdr.request_api_version,
                       req_hdr.correlation_id);
    } else {
        bpf_dbg_printk("====== is_kafka PACKET_TYPE_RESPONSE ======= %d", packet_type);

        if (kafka_parse_fixup_response_header(conn_info, &res_hdr, data, data_len) != 0) {
            bpf_dbg_printk("is_kafka: failed to parse kafka response header");
            return 0;
        }
        if (res_hdr.message_size > k_kafka_message_size_max) {
            bpf_dbg_printk("is_kafka: response message size is too large: %d",
                           res_hdr.message_size);
            return 0;
        }
        bpf_dbg_printk("is_kafka: kafka! message_size %d, correlation_id=%d",
                       res_hdr.message_size,
                       res_hdr.correlation_id);
    }

    *protocol_type = k_protocol_type_kafka;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}