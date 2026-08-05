// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/protocol_http2_helpers.h>
#include <common/tc_common.h>

#include <generictracer/protocol_http.h>
#include <generictracer/protocol_http2.h>
#include <generictracer/protocol_kafka.h>
#include <generictracer/protocol_mysql.h>
#include <generictracer/protocol_postgres.h>
#include <generictracer/protocol_sunrpc.h>
#include <generictracer/protocol_tcp.h>

#include <logger/bpf_dbg.h>

static __noinline void adopt_split_server_traceparent(call_protocol_args_t *args,
                                                      http_info_t *info,
                                                      const unsigned char *header,
                                                      u32 header_len) {
    const tp_info_t previous = info->tp;
    if (!http1_adopt_split_server_traceparent(&info->tp, header, header_len)) {
        return;
    }
    apply_sampling_decision(&info->tp, 1, 1);

    trace_key_t t_key = {
        .extra_id = info->extra_id,
        .p_key =
            {
                .tid = info->task_tid,
                .pid = info->pid.user_pid,
                .ns = info->pid.ns,
            },
    };
    tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);
    if (!existing) {
        info->tp = previous;
        bpf_dbg_printk("Didn't find existing trace for split Traceparent");
        return;
    }

    tp_info_pid_t refreshed = *existing;
    refreshed.tp = info->tp;
    const u8 vt_keyed = (info->task_tid & JAVA_VT_TID_FLAG) != 0;
    if (bpf_map_update_elem(&server_traces, &t_key, &refreshed, BPF_EXIST) == 0 &&
        refresh_server_trace_publications(&args->pid_conn.conn,
                                          &info->server_conn_part,
                                          &refreshed,
                                          info->pid.host_pid,
                                          info->owner_pid_tgid,
                                          info->owner_lw_thread,
                                          vt_keyed) == 0) {
        return;
    }

    info->tp = previous;
    refreshed.tp = previous;
    bpf_map_update_elem(&server_traces, &t_key, &refreshed, BPF_EXIST);
    refresh_server_trace_publications(&args->pid_conn.conn,
                                      &info->server_conn_part,
                                      &refreshed,
                                      info->pid.host_pid,
                                      info->owner_pid_tgid,
                                      info->owner_lw_thread,
                                      vt_keyed);
}

enum split_client_traceparent_adoption : u8 {
    k_split_client_traceparent_unchanged,
    k_split_client_traceparent_adopted,
    k_split_client_traceparent_fail_closed,
};

static __noinline u8 adopt_split_client_traceparent(call_protocol_args_t *args,
                                                    http_info_t *info,
                                                    const unsigned char *header,
                                                    u32 header_len) {
    tp_info_pid_t *candidate = tp_info_backup_mem();
    tp_info_pid_t *working = tp_info_mem();
    if (!candidate || !working) {
        return k_split_client_traceparent_unchanged;
    }
    candidate->tp = info->tp;
    if (!http1_adopt_split_client_traceparent(&candidate->tp, header, header_len)) {
        return k_split_client_traceparent_unchanged;
    }

    const u8 previous_handoff_state = info->handoff_state;
    const outgoing_trace_token_t previous_handoff_token = info->handoff_token;
    const egress_key_t egress = make_egress_key(&args->pid_conn.conn, args->pid_conn.pid, 0);
    *working = (tp_info_pid_t){
        .tp = info->tp,
        .pid = args->pid_conn.pid,
        .valid = 1,
        .written = k_outbound_trace_pending,
        .req_type = EVENT_HTTP_CLIENT,
    };

    if (info->handoff_state == k_http1_client_handoff_exact) {
        if (wire_traceparent_matches_authority(&info->tp, &candidate->tp)) {
            return k_split_client_traceparent_adopted;
        }
        info->handoff_state = k_http1_client_handoff_fail_closed;
        cleanup_http1_client_publication(&args->pid_conn, info, working);
        request_outgoing_trace_handoff_retirement(&egress, &info->handoff_token, NULL, 0);
        return k_split_client_traceparent_fail_closed;
    }

    // The observed wire value becomes per-request state before any exact
    // claim or support publication can contend.
    info->tp = candidate->tp;
    info->handoff_state = k_http1_client_handoff_wire;
    info->handoff_expected = 0;
    cleanup_http1_client_publication(&args->pid_conn, info, working);

    outgoing_trace_token_t token = {};
    u8 exact_generation_present = 0;
    if (http1_client_handoff_is_pending(previous_handoff_state) &&
        outgoing_trace_token_valid(&previous_handoff_token)) {
        token = previous_handoff_token;
        exact_generation_present = 1;
    } else if (args->handoff_expected) {
        token = args->handoff_token;
        exact_generation_present = 1;
    } else {
        const outgoing_trace_token_t *located =
            bpf_map_lookup_elem(&outgoing_trace_handoff_locators, &egress);
        if (located) {
            token = *located;
            exact_generation_present = 1;
        }
    }

    if (!exact_generation_present) {
        *working = http1_client_event_publication(&args->pid_conn, info, k_outbound_trace_written);
        if (publish_http1_client_request(&args->pid_conn, info, working, 1)) {
            cleanup_http1_client_publication(&args->pid_conn, info, working);
        }
        return k_split_client_traceparent_adopted;
    }

    info->handoff_token = token;
    info->handoff_state = k_http1_client_handoff_pending_wire;
    __builtin_memset(working, 0, sizeof(*working));
    const u8 exact_claimed =
        outgoing_trace_token_valid(&token) &&
        claim_outgoing_trace_handoff(
            &egress, &token, args->pid_conn.pid, EVENT_HTTP_CLIENT, NULL, 1, 1, working);
    if (!exact_claimed || working->written != k_outbound_trace_written) {
        if (exact_claimed) {
            release_claimed_outgoing_trace_handoff(&egress, &token);
        }
        return k_split_client_traceparent_adopted;
    }

    if (!wire_traceparent_matches_authority(&working->tp, &info->tp)) {
        release_claimed_outgoing_trace_handoff(&egress, &token);
        info->handoff_state = k_http1_client_handoff_fail_closed;
        *working = http1_client_event_publication(&args->pid_conn, info, k_outbound_trace_written);
        cleanup_http1_client_publication(&args->pid_conn, info, working);
        request_outgoing_trace_handoff_retirement(&egress, &token, NULL, 0);
        return k_split_client_traceparent_fail_closed;
    }

    info->tp = working->tp;
    info->handoff_state = k_http1_client_handoff_exact;
    info->handoff_expected = 1;
    consume_claimed_outgoing_trace_handoff(&egress, &token);
    if (publish_http1_client_request(&args->pid_conn, info, working, 0)) {
        cleanup_http1_client_publication(&args->pid_conn, info, working);
    }
    return k_split_client_traceparent_adopted;
}

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
               (is_http2_or_grpc(args->small_buf, MIN_HTTP2_SIZE) ||
                (!already_tracked_http2(&args->pid_conn) &&
                 looks_like_http2_frames(args->u_buf, args->bytes_len)))) {
        // check after the main if condition to avoid sending the undesired http2 to the tcp parsers
        if (!args->protocols.http2) {
            return 0;
        }
        bpf_dbg_printk("Found HTTP2 or gRPC connection");
        const u8 saw_preface = is_http2_or_grpc(args->small_buf, MIN_HTTP2_SIZE);
        http2_conn_info_data_t *current = current_http2_connection(&args->pid_conn);
        http2_conn_info_data_t *raw =
            bpf_map_lookup_elem(&ongoing_http2_connections, &args->pid_conn);
        const tracked_connection_t *observed_tracker =
            bpf_map_lookup_elem(&connection_tracker, &args->pid_conn.conn);
        const u32 observed_netns = task_netns();
        const u64 observed_connection_time =
            observed_tracker && observed_tracker->netns == observed_netns ? observed_tracker->time
                                                                          : 0;
        if (!saw_preface && !current && raw && raw->connection_time && !observed_connection_time) {
            // connection_tracker is best-effort and may be evicted. A
            // mid-stream heuristic cannot prove that replacing a fenced
            // generation with an unfenced one is safe; wait for a definitive
            // client preface instead.
            return 0;
        }
        if (saw_preface || !current) {
            if (!observed_connection_time) {
                // Never publish an unfenced tuple generation. A preface proves
                // protocol, not socket identity across later tuple reuse.
                return 0;
            }
            http2_server_hpack_lease_key_t replaced_key = {};
            u64 replaced_token = 0;
            http2_conn_info_data_t *replaced =
                bpf_map_lookup_elem(&ongoing_http2_connections, &args->pid_conn);
            if (replaced) {
                replaced_key = http2_server_hpack_lease_key(&args->pid_conn, replaced);
                replaced_token = new_http2_server_hpack_lease_token();
                if (!claim_http2_server_hpack_lease(&replaced_key, replaced_token)) {
                    retire_http2_server_hpack_generation(&replaced_key);
                    return 0;
                }
                replaced = bpf_map_lookup_elem(&ongoing_http2_connections, &args->pid_conn);
                if (!http2_server_hpack_generation_matches(
                        &replaced_key, &args->pid_conn, replaced)) {
                    release_http2_server_hpack_lease(&replaced_key, replaced_token);
                    return 0;
                }
                http2_server_hpack_lease_t *replaced_lease =
                    bpf_map_lookup_elem(&http2_server_hpack_leases, &replaced_key);
                if (!replaced_lease || replaced_lease->token != replaced_token) {
                    release_http2_server_hpack_lease(&replaced_key, replaced_token);
                    return 0;
                }
                // Delete before inserting the new generation. A tail-call
                // chain retaining the old RCU value can no longer write into
                // the replacement value in place.
                bpf_map_delete_elem(&ongoing_http2_connections, &args->pid_conn);
                bpf_map_delete_elem(&http2_server_hpack_states, &replaced_key);
            }

            http2_conn_info_data_t *data = empty_http2_conn_info();
            if (!data) {
                release_http2_server_hpack_lease(&replaced_key, replaced_token);
                return 0;
            }
            data->id = uniqueHTTP2ConnId(&args->pid_conn);
            data->process_start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS();
            data->connection_time = observed_connection_time;
            data->flags = http2_conn_flag_new;
            data->retired = 0;
            if (args->ssl) {
                data->flags |= http2_conn_flag_ssl;
            }
            const http2_server_hpack_lease_key_t new_key =
                http2_server_hpack_lease_key(&args->pid_conn, data);
            const u8 state_inserted =
                data->process_start_time && insert_http2_server_hpack_state(&new_key, 0);
            long update_result =
                state_inserted ? bpf_map_update_elem(
                                     &ongoing_http2_connections, &args->pid_conn, data, BPF_NOEXIST)
                               : -1;
            if (update_result != 0 && state_inserted) {
                bpf_map_delete_elem(&http2_server_hpack_states, &new_key);
            } else if (update_result == 0 && !current_http2_connection(&args->pid_conn)) {
                // The tracker changed after publication. Logical retirement
                // makes A immediately non-routable without an ABA-prone tuple
                // delete; the next exact lease owner reclaims it.
                retire_http2_server_hpack_generation(&new_key);
                update_result = -1;
            }
            release_http2_server_hpack_lease(&replaced_key, replaced_token);
            if (update_result != 0 && !current_http2_connection(&args->pid_conn)) {
                return 0;
            }
        }
        skip_http2_preface(args);
    }

    http2_conn_info_data_t *h2g = current_http2_connection(&args->pid_conn);
    if (h2g && (http2_flag_ssl(h2g->flags) == args->ssl)) {
        // check after the main if condition to avoid sending the undesired http2 to the tcp parsers
        if (!args->protocols.http2) {
            return 0;
        }
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2);
        if (request_type_by_direction(args->direction, PACKET_TYPE_REQUEST) == EVENT_HTTP_REQUEST) {
            const http2_server_hpack_lease_key_t failed_key =
                http2_server_hpack_lease_key(&args->pid_conn, h2g);
            retire_http2_server_hpack_generation(&failed_key);
        }
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
    } else if (args->protocols.tcp && is_mssql(&args->pid_conn.conn,
                                               (const unsigned char *)args->u_buf,
                                               args->bytes_len,
                                               &args->protocol_type)) {
        bpf_dbg_printk("Found mssql connection");
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);
    } else if (args->protocols.tcp && is_kafka(&args->pid_conn.conn,
                                               (const unsigned char *)args->u_buf,
                                               args->bytes_len,
                                               &args->protocol_type,
                                               args->direction)) {
        bpf_dbg_printk("Found kafka connection");
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);
    } else if (args->protocols.tcp && is_sunrpc(&args->pid_conn.conn,
                                                (const unsigned char *)args->u_buf,
                                                args->bytes_len,
                                                &args->protocol_type)) {
        bpf_dbg_printk("Found SunRPC connection");
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);
    } else {
        bpf_tail_call_static(ctx, &jump_table, k_tail_handle_http_continuation);
    }

    return 0;
}

SEC("kprobe")
int obi_handle_http_continuation(void *ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);

    bpf_d_printk("http info %llx, submitted %d, still reading %d",
                 info,
                 (info) ? info->submitted : 0,
                 (info) ? still_reading(info) : 0);

    if (args->protocols.http && info && !info->submitted) {
        if (info->ssl && !args->ssl) {
            return 0;
        }

        const u8 reading = still_reading(info);
        const u8 responding = still_responding(info);
        // Still reading checks if we are processing buffers of a HTTP request
        // that has started, but we haven't seen a response yet.
        if (reading || responding) {
            if (info->type == EVENT_HTTP_CLIENT &&
                http1_client_handoff_is_pending(info->handoff_state)) {
                resolve_pending_http1_client_handoff(&args->pid_conn, info, 0);
            }
            if (reading && info->awaiting_split_traceparent) {
                const enum http1_split_traceparent_role role = http1_split_traceparent_role(
                    info->type, args->direction, info->awaiting_split_traceparent, args->bytes_len);

                if (role != k_http1_split_traceparent_none) {
                    unsigned char *buf = (unsigned char *)tp_char_buf_mem();
                    u32 buf_len = args->bytes_len;
                    bpf_clamp_umax(buf_len, k_http1_split_traceparent_max_len);
                    if (buf && !bpf_probe_read(buf, buf_len, (unsigned char *)args->u_buf)) {
                        if (role == k_http1_split_traceparent_server) {
                            adopt_split_server_traceparent(args, info, buf, buf_len);
                        } else {
                            adopt_split_client_traceparent(args, info, buf, buf_len);
                        }
                    }
                }
                // The one-shot fragment is now either durably adopted or
                // definitively unavailable. Resume large-buffer capture.
                info->awaiting_split_traceparent = 0;
                info->suppress_large_buffers = 0;
            }

            u8 packet_type = PACKET_TYPE_REQUEST;
            if (responding) {
                packet_type = PACKET_TYPE_RESPONSE;
            }

            if (reading) {
                info->len += args->bytes_len;
            } else if (responding) {
                info->end_monotime_ns = bpf_ktime_get_ns();
                bpf_d_printk("bytes len %d, new bytes %d", info->resp_len, args->bytes_len);
                info->resp_len += args->bytes_len;
            }

            http_send_large_buffer(ctx,
                                   info,
                                   &args->pid_conn,
                                   (void *)args->u_buf,
                                   args->bytes_len,
                                   packet_type,
                                   args->direction,
                                   k_large_buf_action_append);
        }
    } else if (args->protocols.tcp && !info) {
        // SSL requests will see both TCP traffic and text traffic, ignore the TCP if
        // we are processing SSL request. HTTP2 is already checked in handle_buf_with_connection.
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);
    }

    return 0;
}
