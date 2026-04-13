// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/tc_common.h>

#include <generictracer/protocol_http.h>
#include <generictracer/protocol_http2.h>
#include <generictracer/protocol_kafka.h>
#include <generictracer/protocol_mysql.h>
#include <generictracer/protocol_postgres.h>
#include <generictracer/protocol_tcp.h>

#include <logger/bpf_dbg.h>

// k_tail_handle_buf_with_args
SEC("kprobe")
int obi_handle_buf_with_args(void *ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe buf=[%s], pid=%d, len=%d ===",
                   args->small_buf,
                   args->pid_conn.pid,
                   args->bytes_len);

    if (args->protocols.http && is_http(args->small_buf, MIN_HTTP_SIZE, &args->packet_type)) {
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http);
    } else if ((args->protocol_type != k_protocol_type_http) &&
               is_http2_or_grpc(args->small_buf, MIN_HTTP2_SIZE)) {
        // check after the main if condition to avoid sending the undesired http2 to the tcp parsers
        if (!args->protocols.http2) {
            return 0;
        }
        bpf_dbg_printk("Found HTTP2 or gRPC connection");
        http2_conn_info_data_t data = {
            .id = 0,
            .flags = http2_conn_flag_new,
        };
        data.id = uniqueHTTP2ConnId(&args->pid_conn);
        if (args->ssl) {
            data.flags |= http2_conn_flag_ssl;
        }
        bpf_map_update_elem(&ongoing_http2_connections, &args->pid_conn, &data, BPF_ANY);
        // if we detected the preface, parse any grpc past the preface
        if (has_preface(args->small_buf, args->bytes_len) && args->bytes_len > MIN_HTTP2_SIZE) {
            args->u_buf = args->u_buf + MIN_HTTP2_SIZE;
        }
    }

    http2_conn_info_data_t *h2g = bpf_map_lookup_elem(&ongoing_http2_connections, &args->pid_conn);
    if (h2g && (http2_flag_ssl(h2g->flags) == args->ssl)) {
        // check after the main if condition to avoid sending the undesired http2 to the tcp parsers
        if (!args->protocols.http2) {
            return 0;
        }
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2);
    } else if (args->protocols.tcp && is_mysql(&args->pid_conn.conn,
                                               (const unsigned char *)args->u_buf,
                                               args->bytes_len,
                                               &args->protocol_type)) {
        bpf_dbg_printk("Found mysql connection");
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);
    } else if (args->protocols.tcp && is_postgres(&args->pid_conn.conn,
                                                  (const unsigned char *)args->u_buf,
                                                  args->bytes_len,
                                                  &args->protocol_type)) {
        bpf_dbg_printk("Found postgres connection");
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);
    } else if (args->protocols.tcp && is_kafka(&args->pid_conn.conn,
                                               (const unsigned char *)args->u_buf,
                                               args->bytes_len,
                                               &args->protocol_type,
                                               args->direction)) {
        bpf_dbg_printk("Found kafka connection");
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);
    } else { // large request tracking and generic TCP
        http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);

        bpf_d_printk("http info %llx, submitted %d, still reading %d",
                     info,
                     (info) ? info->submitted : 0,
                     (info) ? still_reading(info) : 0);

        if (args->protocols.http && info && !info->submitted) {
            const u8 reading = still_reading(info);
            const u8 responding = still_responding(info);
            // Still reading checks if we are processing buffers of a HTTP request
            // that has started, but we haven't seen a response yet.
            if (reading || responding) {
                // Packets are split into chunks if OBI injected the Traceparent
                // Make sure you look for split packets containing the real Traceparent.
                // Essentially, when a packet is extended by our sock_msg program and
                // passed down another service, the receiving side may reassemble the
                // packets into one buffer or not. If they are reassembled, then the
                // call to bpf_tail_call(ctx, &jump_table, k_tail_protocol_http); will
                // scan for the incoming 'Traceparent' header. If they are not reassembled
                // we'll see something like this:
                // [before the injected header],[70 bytes for 'Traceparent...'],[the rest].
                if (reading && is_traceparent(args->small_buf)) {
                    unsigned char *buf = (unsigned char *)tp_char_buf_mem();
                    if (buf) {
                        bpf_probe_read(buf, TP_SIZE, (unsigned char *)args->u_buf);
                        bpf_dbg_printk("Found traceparent buf=[%s]", buf);
                        unsigned char *t_id = extract_trace_id(buf);
                        unsigned char *s_id = extract_span_id(buf);
                        unsigned char *f_id = extract_flags(buf);

                        decode_hex(info->tp.trace_id, t_id, TRACE_ID_CHAR_LEN);
                        decode_hex((unsigned char *)&info->tp.flags, f_id, FLAGS_CHAR_LEN);
                        decode_hex(info->tp.parent_id, s_id, SPAN_ID_CHAR_LEN);

                        trace_key_t t_key = {0};
                        trace_key_from_pid_tid(&t_key);

                        tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);
                        if (existing) {
                            existing->tp = info->tp;
                            set_trace_info_for_connection(
                                &args->pid_conn.conn, TRACE_TYPE_SERVER, existing);
                        } else {
                            bpf_dbg_printk("Didn't find existing trace, this might be a bug!");
                        }
                    }
                }

                u8 packet_type = PACKET_TYPE_REQUEST;
                if (responding) {
                    packet_type = PACKET_TYPE_RESPONSE;
                }

                http_send_large_buffer(info,
                                       (void *)args->u_buf,
                                       args->bytes_len,
                                       packet_type,
                                       args->direction,
                                       k_large_buf_action_append);

                if (reading) {
                    info->len += args->bytes_len;
                } else if (responding) {
                    info->end_monotime_ns = bpf_ktime_get_ns();
                    bpf_d_printk("bytes len %d, new bytes %d", info->resp_len, args->bytes_len);
                    info->resp_len += args->bytes_len;
                }
            }
        } else if (args->protocols.tcp && !info) {
            // SSL requests will see both TCP traffic and text traffic, ignore the TCP if
            // we are processing SSL request. HTTP2 is already checked in handle_buf_with_connection.
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);
        }
    }

    return 0;
}