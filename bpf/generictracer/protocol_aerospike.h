// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/connection_info.h>
#include <common/large_buf_emit.h>
#include <common/large_buffers.h>
#include <common/map_sizing.h>
#include <common/ringbuf.h>

#include <generictracer/maps/protocol_cache.h>

#include <logger/bpf_dbg.h>

// Aerospike native client protocol ("proto" version 2).
//
// Every message starts with an 8-byte proto header:
//   version(1) = 2, type(1), size(6, big-endian) = body length
// Only type-3 AS_MSG data frames produce spans. Their body begins with a fixed
// 22-byte as_msg header whose first byte is its own size (22), which makes the
// (version, type, header_sz) triple a strong classification signature for both
// requests and responses. Parsing happens in userspace:
// pkg/ebpf/common/aerospike_detect_transform.go.

enum {
    k_aerospike_proto_header_len = 8,
    k_aerospike_proto_version = 2,
    k_aerospike_msg_type_as_msg = 3,
    k_aerospike_as_msg_header_len = 22,
    // largest declared proto body we treat as plausibly Aerospike;
    // matches asMaxBodyLen in the userspace parser
    k_aerospike_max_body_len = 128 * 1024 * 1024,
};

static __always_inline u64 aerospike_body_len(const unsigned char *hdr) {
    return ((u64)hdr[2] << 40) | ((u64)hdr[3] << 32) | ((u64)hdr[4] << 24) | ((u64)hdr[5] << 16) |
           ((u64)hdr[6] << 8) | (u64)hdr[7];
}

static __always_inline u8 is_aerospike(connection_info_t *conn_info,
                                       const unsigned char *data,
                                       u32 data_len,
                                       enum protocol_type *protocol_type) {
    if (*protocol_type == k_protocol_type_aerospike) {
        return 1;
    }
    if (*protocol_type != k_protocol_type_unknown) {
        return 0;
    }

    // require the full proto + as_msg headers so the signature check below is meaningful
    if (data_len < k_aerospike_proto_header_len + k_aerospike_as_msg_header_len) {
        return 0;
    }

    unsigned char hdr[k_aerospike_proto_header_len + 1] = {};
    if (bpf_probe_read(hdr, sizeof(hdr), data) != 0) {
        return 0;
    }

    if (hdr[0] != k_aerospike_proto_version || hdr[1] != k_aerospike_msg_type_as_msg ||
        hdr[8] != k_aerospike_as_msg_header_len) {
        return 0;
    }

    const u64 body_len = aerospike_body_len(hdr);
    if (body_len < k_aerospike_as_msg_header_len || body_len > k_aerospike_max_body_len) {
        return 0;
    }

    *protocol_type = k_protocol_type_aerospike;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}

// Wire bytes of the first response frame not yet observed on a connection.
// Some clients (e.g. Java) read a response in two steps — the 8-byte proto
// header, then the body — so the frame spans multiple recv() buffers and the
// span event must wait until all of it was seen.
typedef struct aerospike_state_data {
    s64 response_bytes_remaining;
} aerospike_state_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, aerospike_state_data_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} aerospike_state SEC(".maps");

static __always_inline u32 aerospike_emit_chunks(tcp_req_t *req,
                                                 pid_connection_info_t *pid_conn,
                                                 const void *u_buf,
                                                 u32 bytes_len,
                                                 u8 packet_type,
                                                 u8 direction,
                                                 enum large_buf_action action,
                                                 u32 sent_bytes) {
    tcp_large_buffer_t *lb = (tcp_large_buffer_t *)tcp_large_buffers_mem();
    if (!lb) {
        bpf_dbg_printk("failed to reserve space for Aerospike large buffer");
        return 0;
    }

    lb->type = EVENT_TCP_LARGE_BUFFER;
    lb->packet_type = packet_type;
    lb->action = action;
    lb->kind = k_large_buf_layer_app;
    lb->direction = direction;
    lb->conn_info = pid_conn->conn;
    lb->tp = req->tp;
    lb->source = k_large_buffer_source_kprobes;

    u32 max_available_bytes = aerospike_max_captured_bytes - sent_bytes;
    bpf_clamp_umax(max_available_bytes, k_large_buf_max_aerospike_captured_bytes);

    const u32 available_bytes = min(bytes_len, max_available_bytes);
    return large_buf_emit_chunks(lb, u_buf, available_bytes, k_large_buf_read_kernel);
}

// Emit large buffer events for Aerospike and drive response reassembly.
// The return value controls the flow for this protocol:
// -1: wait for more response data before emitting the span event; 0: continue.
static __always_inline int aerospike_send_large_buffer(tcp_req_t *req,
                                                       pid_connection_info_t *pid_conn,
                                                       const void *u_buf,
                                                       u32 bytes_len,
                                                       u8 packet_type,
                                                       u8 direction,
                                                       enum large_buf_action action) {
    if (aerospike_max_captured_bytes == 0 || bytes_len == 0) {
        return 0;
    }

    if (packet_type == PACKET_TYPE_REQUEST) {
        if (req->lb_req_bytes >= aerospike_max_captured_bytes) {
            return 0;
        }
        const u32 consumed = aerospike_emit_chunks(
            req, pid_conn, u_buf, bytes_len, packet_type, direction, action, req->lb_req_bytes);
        req->lb_req_bytes += consumed;
        if (consumed > 0) {
            req->has_large_buffers = true;
        }
        return 0;
    }

    // Response side: reassemble the first frame so its result_code reaches
    // userspace even when the client reads the proto header and the body in
    // separate recv() calls (split read).
    if (req->end_monotime_ns != 0) {
        // The span event was already emitted: these are trailing frames of a
        // streamed scan/query/batch response.
        return 0;
    }

    const bool first_chunk = req->lb_res_bytes == 0;
    s64 remaining = 0;

    if (first_chunk) {
        if (bytes_len < k_aerospike_proto_header_len) {
            return 0;
        }
        unsigned char hdr[k_aerospike_proto_header_len] = {};
        if (bpf_probe_read(hdr, sizeof(hdr), u_buf) != 0) {
            return 0;
        }
        if (hdr[0] != k_aerospike_proto_version) {
            return 0;
        }
        remaining = (s64)(k_aerospike_proto_header_len + aerospike_body_len(hdr));
    } else {
        const aerospike_state_data_t *state =
            bpf_map_lookup_elem(&aerospike_state, &pid_conn->conn);
        if (!state) {
            // The state entry was LRU-evicted mid-capture: finalize with what
            // was captured (possibly truncated) rather than never completing.
            return 0;
        }
        remaining = state->response_bytes_remaining;
    }

    const u32 consumed = aerospike_emit_chunks(
        req, pid_conn, u_buf, bytes_len, packet_type, direction, action, req->lb_res_bytes);
    req->lb_res_bytes += consumed;
    if (consumed > 0) {
        req->has_large_buffers = true;
    }

    // remaining tracks wire bytes of the first frame, so the whole chunk counts
    // even when the capture cap truncated what was emitted.
    remaining -= (s64)bytes_len;

    if (remaining > 0 && req->lb_res_bytes < aerospike_max_captured_bytes) {
        const aerospike_state_data_t state = {.response_bytes_remaining = remaining};
        bpf_map_update_elem(&aerospike_state, &pid_conn->conn, &state, BPF_ANY);
        bpf_dbg_printk("aerospike response incomplete, remaining=%lld, waiting", remaining);
        return -1;
    }

    bpf_map_delete_elem(&aerospike_state, &pid_conn->conn);
    return 0;
}
