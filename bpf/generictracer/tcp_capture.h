// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/large_buffers.h>
#include <generictracer/protocol_aerospike.h>
#include <generictracer/protocol_kafka.h>
#include <generictracer/protocol_mssql.h>
#include <generictracer/protocol_mysql.h>
#include <generictracer/protocol_postgres.h>
#include <generictracer/tcp_multiplex.h>
#include <generictracer/tcp_trace_cleanup.h>

// Emit a single TCP event for the normal classifier chain, with operation ranges when available.
static __always_inline void
emit_tcp_request(tcp_req_t *req, const void *response, u32 response_len) {
    const bool multiplex_emitted = tcp_multiplex_emit(req, response, response_len);
    if (multiplex_emitted) {
        return;
    }

    if (!response) {
        events_ringbuf_output(req, sizeof(*req));
        return;
    }

    tcp_req_t *trace = events_ringbuf_reserve(sizeof(*trace), 0);
    if (!trace) {
        bpf_dbg_printk("failed to reserve space on the ringbuf");
        return;
    }

    bpf_dbg_printk("Sending TCP trace: existing=%lx, resp_length=%d", req, req->resp_len);
    __builtin_memcpy(trace, req, sizeof(*req));
    if (response_len) {
        bpf_clamp_umax(response_len, sizeof(trace->rbuf));
        bpf_probe_read(trace->rbuf, response_len, response);
    }

    bpf_ringbuf_submit(trace, get_flags());
}

// Emit raw socket bytes within the remaining per-direction capture budget.
static __always_inline void unknown_send_large_buffer(tcp_req_t *req,
                                                      pid_connection_info_t *pid_conn,
                                                      const void *u_buf,
                                                      u32 bytes_len,
                                                      u8 packet_type,
                                                      u8 direction,
                                                      enum large_buf_action action) {
    tcp_large_buffer_t *lb = (tcp_large_buffer_t *)tcp_large_buffers_mem();

    if (!lb) {
        bpf_dbg_printk("failed to reserve space for generic TCP large buffer");
        return;
    }

    lb->type = k_event_type_tcp_large_buffer;
    lb->packet_type = packet_type;
    lb->action = action;
    lb->kind = k_large_buf_layer_wire;
    lb->direction = direction;
    lb->conn_info = pid_conn->conn;
    lb->tp = req->tp;
    lb->source = k_large_buffer_source_kprobes;

    u32 bytes_sent = req->lb_res_bytes;
    if (packet_type == PACKET_TYPE_REQUEST) {
        bytes_sent = req->lb_req_bytes;
    }

    u32 max_available_bytes = tcp_max_captured_bytes - bytes_sent;
    u32 consumed_bytes = 0;

    bpf_clamp_umax(max_available_bytes, k_large_buf_max_tcp_captured_bytes);

    const u32 available_bytes = min(bytes_len, max_available_bytes);
    consumed_bytes += large_buf_emit_chunks(lb, u_buf, available_bytes, k_large_buf_read_kernel);

    if (packet_type == PACKET_TYPE_REQUEST) {
        req->lb_req_bytes += consumed_bytes;
    } else {
        req->lb_res_bytes += consumed_bytes;
    }

    if (consumed_bytes > 0) {
        req->has_large_buffers = true;
    }
}

// Route large-buffer capture by protocol. A negative result defers emission until more data arrives.
static __always_inline int tcp_send_large_buffer(tcp_req_t *req,
                                                 pid_connection_info_t *pid_conn,
                                                 void *u_buf,
                                                 int bytes_len,
                                                 u8 direction,
                                                 enum protocol_type protocol_type,
                                                 enum large_buf_action action) {
    const u8 packet_type = infer_packet_type(direction, req->is_server);

    switch (protocol_type) {
    case k_protocol_type_mysql:
        return mysql_send_large_buffer(
            req, pid_conn, u_buf, bytes_len, packet_type, direction, action);
    case k_protocol_type_postgres:
        return postgres_send_large_buffer(req, u_buf, bytes_len, packet_type, direction, action);
    case k_protocol_type_kafka:
        return kafka_send_large_buffer(req, pid_conn, u_buf, bytes_len, direction, action);
    case k_protocol_type_mssql:
        mssql_send_large_buffer(req, u_buf, bytes_len, packet_type, direction, action);
        if (packet_type == PACKET_TYPE_RESPONSE) {
            return mssql_response_eom(req, u_buf, bytes_len);
        }
        return 0;
    case k_protocol_type_http:
    case k_protocol_type_mqtt:
        break;
    case k_protocol_type_sunrpc:
        unknown_send_large_buffer(req, pid_conn, u_buf, bytes_len, packet_type, direction, action);
        break;
    case k_protocol_type_aerospike:
        return aerospike_send_large_buffer(
            req, pid_conn, u_buf, bytes_len, packet_type, direction, action);
    case k_protocol_type_nats:
    case k_protocol_type_amqp:
    case k_protocol_type_unknown:
        unknown_send_large_buffer(req, pid_conn, u_buf, bytes_len, packet_type, direction, action);
        break;
    }

    return 0;
}

// Select the large-buffer byte count for this I/O using the local endpoint's role.
static __always_inline u32 tcp_captured_bytes(const tcp_req_t *req, u8 direction) {
    u8 packet_type = infer_packet_type(direction, req->is_server);
    if (packet_type == PACKET_TYPE_REQUEST) {
        return req->lb_req_bytes;
    }

    return req->lb_res_bytes;
}

// Record the opening I/O using the timestamp and inline bytes already saved by the TCP handler.
static __always_inline void tcp_capture_first(tcp_req_t *req, call_protocol_args_t *args) {
    tcp_send_large_buffer(req,
                          &args->pid_conn,
                          (void *)args->u_buf,
                          args->bytes_len,
                          args->direction,
                          args->protocol_type,
                          k_large_buf_action_init);

    const u32 large = tcp_captured_bytes(req, args->direction);
    const tcp_io_range_t op = {
        .timestamp = req->start_monotime_ns,
        .len = req->req_len,
        .inline_len = req->len,
        .large_len = large,
    };

    tcp_multiplex_record_operation(req, args, &op, args->tcp_previous_record_ts);
}

// Append same-direction bytes and record where this operation lands in each buffer.
static __always_inline void tcp_capture_append(tcp_req_t *req, call_protocol_args_t *args) {
    const u32 len = args->bytes_len;
    tcp_io_range_t op = {.len = len, .large_offset = tcp_captured_bytes(req, args->direction)};

    u32 off = req->len;
    if (off > 0 && off < sizeof(req->buf)) {
        bpf_clamp_umax(off, sizeof(req->buf) - 1);
        const u32 remaining = sizeof(req->buf) - off;
        u32 copy_len = min(len, remaining);

        // The verifier checks max offset + max size against the whole map value.
        // Splitting at the midpoint bounds that estimate while remaining bounds the actual copy.
        enum { midpoint = sizeof(req->buf) / 2 };
        _Static_assert(__builtin_offsetof(tcp_req_t, buf) + sizeof(req->buf) + midpoint <=
                           sizeof(*req),
                       "TCP inline append needs half a buffer after buf for verifier bounds");
        if (off < midpoint) {
            bpf_clamp_umax(copy_len, sizeof(req->buf));
        } else {
            bpf_clamp_umax(copy_len, midpoint);
        }
        const long err = bpf_probe_read(req->buf + off, copy_len, (void *)args->u_buf);
        if (err == 0) {
            op.inline_offset = off;
            op.inline_len = copy_len;
        }
    }

    req->len += len;
    req->req_len = req->len;
    tcp_send_large_buffer(req,
                          &args->pid_conn,
                          (void *)args->u_buf,
                          len,
                          args->direction,
                          args->protocol_type,
                          k_large_buf_action_append);

    op.large_len = tcp_captured_bytes(req, args->direction) - op.large_offset;

    tcp_multiplex_record_operation(req, args, &op, 0);
}

// Emit the TCP record on the first opposite-direction I/O and send subsequent operations as continuations.
static __always_inline void tcp_capture_response(tcp_req_t *req, call_protocol_args_t *args) {
    const bool record_ended = req->end_monotime_ns != 0;
    const bool multiplexed = req->flags == k_event_type_tcp_multiplex;
    const bool unclassified = args->protocol_type == k_protocol_type_unknown;
    const bool continuation = record_ended && multiplexed && unclassified;
    const u32 before = tcp_captured_bytes(req, args->direction);
    enum large_buf_action action = k_large_buf_action_init;
    const bool append_response = !continuation && req->lb_res_bytes != 0;

    if (append_response) {
        action = k_large_buf_action_append;
    }

    const int capture_result = tcp_send_large_buffer(req,
                                                     &args->pid_conn,
                                                     (void *)args->u_buf,
                                                     args->bytes_len,
                                                     args->direction,
                                                     args->protocol_type,
                                                     action);
    if (capture_result < 0) {
        bpf_dbg_printk("waiting additional response data");
        return;
    }

    if (req->end_monotime_ns) {
        if (continuation) {
            const u32 captured_bytes = tcp_captured_bytes(req, args->direction) - before;
            tcp_multiplex_emit_cont(req, args, captured_bytes);
        }

        return;
    }

    // mssql_response_eom retains the start of a response split across socket reads.
    const bool is_mssql = args->protocol_type == k_protocol_type_mssql;
    const u8 packet_type = infer_packet_type(args->direction, req->is_server);
    const bool is_response = packet_type == PACKET_TYPE_RESPONSE;
    const bool response_already_captured = is_mssql && is_response;

    u32 response_len = args->bytes_len;
    u32 inline_len = response_len;
    bpf_clamp_umax(inline_len, k_tcp_res_len);
    req->end_monotime_ns = bpf_ktime_get_ns();

    if (response_already_captured) {
        inline_len = min(req->resp_len, (u32)k_tcp_res_len);
        response_len = 0;
    }

    req->resp_len = inline_len;

    emit_tcp_request(req, (void *)args->u_buf, response_len);

    cleanup_trace_info(req, &args->pid_conn);
}
