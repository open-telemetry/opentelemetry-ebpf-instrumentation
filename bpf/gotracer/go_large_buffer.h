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

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/large_buf_emit.h>
#include <common/large_buffers.h>
#include <common/h2_defs.h>
#include <common/protocol_defs.h>
#include <common/trace_helpers.h>
#include <common/tp_info.h>

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

static __always_inline u8 read_http2_stream_id(const void *buf, s64 len, u32 *stream_id) {
    if (!buf || !stream_id || len < k_h2_frame_header_len) {
        return 0;
    }

    unsigned char encoded[sizeof(*stream_id)];
    const unsigned char *stream_id_pos = (const unsigned char *)buf + k_h2_frame_stream_id_offset;
    if (bpf_probe_read_user(encoded, sizeof(encoded), stream_id_pos) != 0) {
        return 0;
    }

    *stream_id = ((u32)(encoded[0] & 0x7f) << 24) | ((u32)encoded[1] << 16) |
                 ((u32)encoded[2] << 8) | (u32)encoded[3];
    return 1;
}

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
cleanup_ongoing_large_buffer_sorted_conn(const connection_info_t *sorted_conn, u32 stream_id) {
    go_large_buffer_key_t key = {.conn = *sorted_conn, .stream_id = stream_id};

    bpf_map_delete_elem(&ongoing_large_buffers, &key);
}

// General idea on how this works.
// For HTTP1.1 we simply track the connection info and the request kind by
// using the same approach we use in kprobes, i.e. we look at the first few
// bytes in the buffer and determine if it's a request or a response.
// For HTTP2 we need help. At the moment only Go HTTP2 client is implemented.
// The main issue is that the Go HTTP2 client responses are done by a common
// single goroutine reader, so we cannot easily correlate the request and the
// response. There are multiple requests per connection and not the same
// goroutine. We setup what we need in setup_http2_client_conn, which runs for
// HTTP2 client connections before any packet is sent. That probe tells us it's
// HTTP2 connection we are dealing with and has setup metadata on the parent
// goroutine for the first initial write for the traceparent.
// Given how the HTTP2 client send/receive work in Go, we should always read a frame
// that has stream id. If we read mid-stream, it's possible that this will not work
// and it's a limitation to the current code.
static __always_inline void ship_large_request(void *buf,
                                               s64 len,
                                               go_addr_key_t *g_key,
                                               const connection_info_t *conn,
                                               u8 event_type,
                                               u8 direction) {
    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)tcp_large_buffers_mem();
    if (!large_buf) {
        return;
    }

    http_func_invocation_t *invocation = NULL;

    large_buf->conn_info = *conn;
    sort_connection_info(&large_buf->conn_info);

    // We assume no streamID, e.g. HTTP1.1
    go_large_buffer_key_t prev_key = {.conn = large_buf->conn_info, // sorted
                                      .stream_id = 0};

    bool *is_http2_conn = bpf_map_lookup_elem(&go_http2_client_connections, &large_buf->conn_info);

    // If we were told it's HTTP2 connection by the setup_http2_client_conn uprobe, we try to
    // read the streamid. Each HTTP2 frame must have it, otherwise the HTTP2 reader cannot
    // tie the buffer to the individual request.
    if (is_http2_conn) {
        if (read_http2_stream_id(buf, len, &prev_key.stream_id)) {
            bpf_d_printk("http2 stream_id=%d", prev_key.stream_id);
        } else {
            return;
        }
    }

    u8 is_http = go_is_http(buf, MIN_HTTP_SIZE);

    go_large_buffer_req_t *prev_event = bpf_map_lookup_elem(&ongoing_large_buffers, &prev_key);

    if (prev_event) {
        event_type = prev_event->event_type;
    } else {
        // Not HTTP and no previous event means it's HTTP2. The metadata is not
        // attached to our goroutine, since the writer is spawned by the actual
        // request. So we lookup the goroutine parent. Again this only handles
        // client HTTP2 for now, server would need more work.
        if (is_http == k_http_not) {
            void *parent_go = (void *)find_parent_goroutine_in_chain(g_key);

            bpf_d_printk("parent_go %llx", parent_go);

            if (parent_go) {
                go_addr_key_t parent_g = {};
                go_addr_key_from_id(&parent_g, parent_go);

                invocation = bpf_map_lookup_elem(&go_ongoing_http_client_requests, &parent_g);
                // invocation contains our traceparent info. For HTTP2 clients this is a must
                // since there are more than one request multiplexed on the same connection.
                if (invocation) {
                    bpf_d_printk("found client go on parent %llx", parent_go);
                    event_type = k_lb_event_type_client;
                    is_http = k_http_request;
                }
            }
        }
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
        if (!prev_event) {
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
    large_buf->action = (!prev_event || is_http != k_http_not) ? k_large_buf_action_init
                                                               : k_large_buf_action_append;
    large_buf->kind = k_large_buf_layer_app;
    large_buf->source = k_large_buffer_source_go;
    tp_info_t empty = {0};
    // If we have a previous event, keep propagating it's traceparent. For HTTP2 client
    // we can only find the trace parent information on the write (outgoing) requests.
    if (prev_event) {
        large_buf->tp = prev_event->tp;
    } else if (invocation) { // HTTP2 client first time with invocation.
        large_buf->tp = invocation->tp;
    } else {
        large_buf->tp = empty;
    }

    if (is_http == k_http_request) {
        go_large_buffer_req_t event = {.event_type = event_type};
        event.tp = large_buf->tp;

        bpf_map_update_elem(&ongoing_large_buffers, &prev_key, &event, BPF_ANY);
    }

    large_buf_emit_chunks(large_buf, buf, len, k_large_buf_read_user);
}

static __always_inline bool http_large_buffers_enabled() {
    return http_max_captured_bytes > 0;
}

static __always_inline bool http_large_buffer_skip(s64 len) {
    return !http_large_buffers_enabled() || len >= http_max_captured_bytes || len <= 0;
}

static __always_inline void send_http_large_buffers_if_needed(
    go_addr_key_t *g_key, connection_info_t *conn, void *buf, s64 len, u8 direction) {

    if (conn) {
        u8 event_type = k_lb_event_type_unknown;

        ship_large_request(buf, len, g_key, conn, event_type, direction);
    }
}
