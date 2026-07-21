// Copyright The OpenTelemetry Authors
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "common/tp_info.h"
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/large_buf_emit.h>
#include <common/large_buffers.h>
#include <common/trace_helpers.h>
#include <common/protocol_defs.h>

#include <gotracer/go_common.h>
#include <maps/go_ongoing_http_client_requests.h>

#include <gotracer/types/go_large_buffer_req.h>
#include <gotracer/types/net_args.h>
#include <gotracer/types/nethttp.h>

#include <gotracer/maps/ongoing_large_buffers.h>
#include <gotracer/maps/nethttp.h>

#include <logger/bpf_dbg.h>

enum {
    k_http_not = 0,
    k_http_request = 1,
    k_http_response = 2,
};

enum { k_lb_event_type_unknown = 0, k_lb_event_type_server = 1, k_lb_event_type_client = 2 };

static __always_inline u8 go_is_http(const unsigned char *buf, u32 len) {
    if (len < MIN_HTTP_SIZE) {
        return 0;
    }
    unsigned char p[MIN_HTTP2_SIZE];
    bpf_probe_read(p, MIN_HTTP2_SIZE, (void *)buf);

    bpf_d_printk("%s", p);

    //HTTP/1.x
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P') && (p[4] == '/') &&
        (p[5] == '1') && (p[6] == '.')) {
        return k_http_response;
    } else if (is_http_request_buf(p)) {
        return k_http_request;
    }

    return k_http_not;
}

static __always_inline void
ship_large_request(void *buf, s64 len, const connection_info_t *conn, u8 event_type, u8 direction) {
    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)tcp_large_buffers_mem();
    if (!large_buf) {
        return;
    }

    large_buf->conn_info = *conn;
    sort_connection_info(&large_buf->conn_info);

    u8 *prev_event_type = bpf_map_lookup_elem(&ongoing_large_buffers, &large_buf->conn_info);

    u8 is_http = go_is_http(buf, MIN_HTTP_SIZE);

    if (prev_event_type) {
        event_type = *prev_event_type;
    }

    u8 packet_type = PACKET_TYPE_REQUEST;
    if (is_http == k_http_request && event_type == k_lb_event_type_unknown) {
        if (direction == TCP_SEND) {
            event_type = k_lb_event_type_client;
        } else {
            event_type = k_lb_event_type_server;
        }
    }

    bpf_d_printk("event type = %d, is_http = %d", event_type, is_http);

    if ((event_type == k_lb_event_type_server && direction == TCP_SEND) ||
        (event_type == k_lb_event_type_client && direction == TCP_RECV)) {
        packet_type = PACKET_TYPE_RESPONSE;
    } else if (event_type == k_lb_event_type_unknown) {
        if (!prev_event_type) {
            // We don't know what this is, likely HTTP2 which
            // we can't handle
            return;
        }
        if (is_http == k_http_response) {
            packet_type = PACKET_TYPE_RESPONSE;
        }
    }

    bpf_d_printk("event_type %d, packet_type %d, is_http %d", event_type, packet_type, is_http);

    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->packet_type = packet_type;
    large_buf->direction = direction;
    large_buf->action = (!prev_event_type || is_http != k_http_not) ? k_large_buf_action_init
                                                                    : k_large_buf_action_append;
    large_buf->kind = k_large_buf_layer_app;
    large_buf->source = k_large_buffer_source_go;
    tp_info_t empty = {0};
    large_buf->tp = empty;

    if (is_http == k_http_request) {
        bpf_map_update_elem(&ongoing_large_buffers, &large_buf->conn_info, &event_type, BPF_ANY);
    }

    large_buf_emit_chunks(large_buf, buf, len, k_large_buf_read_user);
}

static __always_inline bool http_large_buffers_enabled() {
    return http_max_captured_bytes > 0;
}

static __always_inline bool http_large_buffer_skip(s64 len) {
    return !http_large_buffers_enabled() || len >= http_max_captured_bytes || len <= 0;
}

static __always_inline void
send_http_large_buffers_if_needed(connection_info_t *conn, void *buf, s64 len, u8 direction) {

    if (conn) {
        u8 event_type = k_lb_event_type_unknown;

        ship_large_request(buf, len, conn, event_type, direction);
    }
}
