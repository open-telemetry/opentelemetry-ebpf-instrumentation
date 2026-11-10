// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/connection_info.h>
#include <common/event_defs.h>
#include <common/http_types.h>
#include <common/http_trace_parent.h>
#include <common/large_buffers.h>
#include <common/lw_thread.h>
#include <common/preempt_guard.h>
#include <common/ringbuf.h>
#include <common/runtime.h>
#include <common/sampling.h>
#include <common/scratch_mem.h>
#include <common/trace_helpers.h>
#include <common/trace_lifecycle.h>
#include <common/trace_parent.h>
#include <common/tracked_connection.h>

#include <generictracer/maps/http_info_mem.h>
#include <generictracer/maps/http1_header_scans.h>
#include <generictracer/maps/java_http1_requests.h>

#include <generictracer/k_tracer_tailcall.h>
#include <generictracer/large_buf_tailcall.h>
#include <generictracer/http_event.h>
#include <generictracer/http_server_trace.h>
#include <generictracer/protocol_common.h>
#include <generictracer/tcp_trace_cleanup.h>

#include <logger/bpf_dbg.h>

#include <maps/active_ssl_connections.h>
#include <maps/connection_tracker.h>
#include <maps/ongoing_http.h>
#include <maps/tp_info_mem.h>
#include <maps/tp_char_buf_mem.h>

// empty_http_info zeroes and return the unique percpu copy in the map
// this function assumes that a given thread is not trying to use many
// instances at the same time
static __always_inline http_info_t *empty_http_info() {
    int zero = 0;
    http_info_t *value = bpf_map_lookup_elem(&http_info_mem, &zero);
    if (value) {
        __builtin_memset(value, 0, sizeof(http_info_t));
    }
    return value;
}

static __always_inline u32 trace_type_from_meta(http_connection_metadata_t *meta) {
    if (meta->type == k_event_type_http_client) {
        return TRACE_TYPE_CLIENT;
    }

    return TRACE_TYPE_SERVER;
}

static __always_inline u8 is_http(const unsigned char *p, u32 len, u8 *packet_type) {
    if (len < MIN_HTTP_SIZE) {
        return 0;
    }
    //HTTP/1.x
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P') && (p[4] == '/') &&
        (p[5] == '1') && (p[6] == '.')) {
        *packet_type = PACKET_TYPE_RESPONSE;
        return 1;
    } else if (is_http_request_buf(p)) {
        *packet_type = PACKET_TYPE_REQUEST;
        return 1;
    }

    return 0;
}

static __always_inline u8 http_will_complete(http_info_t *info, unsigned char *buf, u32 len) {
    if (info->start_monotime_ns != 0) {
        u8 packet_type;
        unsigned char small_buf[MIN_HTTP2_SIZE];
        bpf_probe_read(small_buf, MIN_HTTP2_SIZE, (void *)buf);
        if (is_http(small_buf, len, &packet_type)) {
            return packet_type == PACKET_TYPE_RESPONSE;
        }
    }

    return false;
}

static __always_inline u8 is_duplicate_info(http_info_t *info) {
    const u64 ts = bpf_ktime_get_ns();
    return info->start_monotime_ns && (ts >= info->start_monotime_ns) &&
           current_immediate_epoch(ts) == current_immediate_epoch(info->start_monotime_ns);
}

static __always_inline void cleanup_http_info(pid_connection_info_t *pid_conn) {
    bpf_map_delete_elem(&ongoing_http, pid_conn);
}

static __always_inline void cleanup_http_server_response_data(pid_connection_info_t *pid_conn,
                                                              http_info_t *info) {
    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_SERVER);
    // Virtual-thread requests do not own the carrier thread's obi_ctx.
    if (!(info->task_tid & JAVA_VT_TID_FLAG)) {
        obi_ctx__del(bpf_get_current_pid_tgid());
    }
}

static __always_inline void cleanup_http_server_thread_trace(http_info_t *info,
                                                             const trace_key_t *current_key) {
    trace_key_t local_key = {0};
    if (!current_key) {
        if (info->delayed) {
            trace_key_from_pid_tid(&local_key);
        }
        current_key = &local_key;
    }

    cleanup_http_server_thread_trace_for_key(info, current_key);
}

static __always_inline void
cleanup_incomplete_http_server_thread_trace(http_info_t *info, const trace_key_t *current_key) {
    if (info->type == k_event_type_http_request && !http_info_complete(info)) {
        cleanup_http_server_thread_trace(info, current_key);
    }
}

static __always_inline void mark_http_server_thread_trace_response_sent(http_info_t *info) {
    trace_key_t t_key = {0};
    tp_info_pid_t *existing = http_server_thread_trace(info, &t_key);
    if (!existing) {
        return;
    }

    if (existing->valid) {
        existing->response_sent = 1;
    } else {
        // Invalid traces cannot parent late children.
        bpf_map_delete_elem(&server_traces, &t_key);
    }
}

static __always_inline void
finish_http(http_info_t *info, pid_connection_info_t *pid_conn, const trace_key_t *current_key) {
    bpf_map_delete_elem(&http1_header_scans, pid_conn);
    if (!http_info_emittable(info)) {
        return;
    }

    submit_http_event(info);

    if (info->type == k_event_type_http_request) {
        cleanup_http_server_thread_trace(info, current_key);
        if (http_server_index_enabled()) {
            unindex_http_server_trace(pid_conn->pid, &info->tp);
        }
    }
    // Don't delete the ongoing_http entry for requests that weren't delayed, we might be
    // receiving still more packets, for example SSL.
    if (info->delayed) {
        bpf_map_delete_elem(&ongoing_http, pid_conn);
    }

    bpf_map_delete_elem(&active_ssl_connections, pid_conn);
}

static __always_inline u64 http_response_bytes_from_sock(struct sock *sk, u8 type) {
    if (!sk) {
        return 0;
    }

    if (type == k_event_type_http_request) {
        return BPF_CORE_READ((struct tcp_sock *)sk, bytes_sent);
    }

    return BPF_CORE_READ((struct tcp_sock *)sk, bytes_received);
}

static __always_inline void force_finish_http(http_info_t *info,
                                              pid_connection_info_t *pid_conn,
                                              const trace_key_t *current_key,
                                              u64 response_bytes) {
    if (info->submitted) {
        return;
    }

    if (!high_request_volume) {
        // A record that already saw its response unparsed is timed from those bytes, so
        // the teardown neither ends it nor tells us anything new about it.
        if (!http_info_complete(info) && info->response_observation == http_response_parsed) {
            // status stays 0: nothing was parsed, so there is no status to report.
            info->resp_len = 0;
            info->end_monotime_ns = bpf_ktime_get_ns();
            info->response_observation =
                http_response_observation_at_close(info->response_bytes_at_request, response_bytes);
        }
    }

    finish_http(info, pid_conn, current_key);
}

static __always_inline void update_http_sent_len(pid_connection_info_t *pid_conn, int sent_len) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info) {
        info->resp_len += sent_len;
    }
}

static __always_inline http_info_t *get_or_set_http_info(http_info_t *info,
                                                         pid_connection_info_t *pid_conn,
                                                         u8 packet_type,
                                                         u8 direction,
                                                         struct sock *sk) {
    if (packet_type == PACKET_TYPE_REQUEST) {
        // this connection was read as an unknown protocol before it spoke HTTP:
        // that TCP request never completes, so its trace would otherwise keep
        // parenting everything this thread does next
        cleanup_tcp_trace_info_if_needed(pid_conn);

        http_info_t *old_info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
        if (old_info && !old_info->submitted) {
            const u8 req_type = request_type_by_direction(direction, packet_type);
            if (!http_info_complete(old_info)) {
                // A record whose response already arrived is finished, whatever came of
                // the parse, so a request in the same epoch is the next call on a reused
                // connection rather than a second sighting of this one.
                const u64 response_bytes = http_response_bytes_from_sock(sk, old_info->type);
                if (old_info->type == req_type && http_response_pending(old_info, response_bytes) &&
                    is_duplicate_info(old_info)) {
                    return 0;
                }
                cleanup_incomplete_http_server_thread_trace(old_info, NULL);
                note_displaced_by_next_request(old_info, bpf_ktime_get_ns());
            }
            // this will delete ongoing_http for this connection info if there's full stale request
            finish_http(old_info, pid_conn, NULL);
        }

        bpf_map_delete_elem(&http1_header_scans, pid_conn);
        bpf_map_update_elem(&ongoing_http, pid_conn, info, BPF_ANY);
    }

    return bpf_map_lookup_elem(&ongoing_http, pid_conn);
}

static __always_inline tp_info_t *self_referencing_request(pid_connection_info_t *pid_conn,
                                                           u8 packet_type) {
    if (packet_type == PACKET_TYPE_REQUEST) {
        http_info_t *old_info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
        if (old_info && !http_info_complete(old_info) &&
            old_info->type == k_event_type_http_client) {
            bpf_dbg_printk("found self referencing request, remembering the old tp info parent_id");
            return &old_info->tp;
        }
    }

    return 0;
}

static __always_inline void finish_possible_delayed_http_request(pid_connection_info_t *pid_conn) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info && info->delayed) {
        finish_http(info, pid_conn, NULL);
    }
}

static __always_inline void force_finish_possible_delayed_http_request(
    pid_connection_info_t *pid_conn, const trace_key_t *current_key, struct sock *sk) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info) {
        cleanup_incomplete_http_server_thread_trace(info, current_key);
        if (info->delayed) {
            finish_http(info, pid_conn, current_key);
        } else {
            bpf_dbg_printk("forcing HTTP event finish");
            force_finish_http(
                info, pid_conn, current_key, http_response_bytes_from_sock(sk, info->type));
        }
    }
    cleanup_http_info(pid_conn);
}

static __always_inline void terminate_http_request_if_needed(pid_connection_info_t *pid_conn,
                                                             const trace_key_t *current_key) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info) {
        if (info->type == k_event_type_http_request) {
            cleanup_http_server_response_data(pid_conn, info);
            cleanup_http_server_thread_trace(info, current_key);
        } else {
            delete_client_trace_info(pid_conn);
        }
    }
    bpf_map_delete_elem(&active_ssl_connections, pid_conn);
}

static __always_inline void process_http_request(http_info_t *info,
                                                 int len,
                                                 http_connection_metadata_t *meta,
                                                 int direction,
                                                 u16 orig_dport,
                                                 lw_thread_t lw_thread,
                                                 struct sock *sk) {
    // Set pid and type early as best effort in case the request times out or dies.
    if (meta) {
        info->pid = meta->pid;
        info->type = meta->type;
    } else {
        if (direction == TCP_RECV) {
            info->type = k_event_type_http_request;
        } else {
            info->type = k_event_type_http_client;
        }
        task_pid(&info->pid);
    }

    fixup_connection_info(&info->conn_info, info->type == k_event_type_http_client, orig_dport);

    u64 start_time = bpf_ktime_get_ns();
    u64 req_time = start_time;

    tracked_connection_t *t_conn = bpf_map_lookup_elem(&connection_tracker, &info->conn_info);
    if (t_conn) {
        if (t_conn->time) {
            bpf_d_printk("prev_start_time=%ld, actual_start_time=%ld [%s]",
                         start_time,
                         t_conn->time,
                         __FUNCTION__);
            req_time = t_conn->time;
            // Splitting client calls with in-queue and processing can be noisy in traces.
            // We want to record the earlier time, but we don't want to split them, therefore
            // we set both start_time and req_time to the same earlier value.
            if (info->type == k_event_type_http_client) {
                start_time = req_time;
            }
        }
        // set the time to zero in case the connection is reused, so we don't produce wrong info
        // but keep the connection info around so that we can tell which connections are valid
        // in the socket filter
        t_conn->time = 0;
    }

    info->start_monotime_ns = start_time;
    info->req_monotime_ns = req_time;
    info->status = 0;
    info->submitted = 0;
    info->response_observation = http_response_parsed;
    info->response_bytes_at_request = http_response_bytes_from_sock(sk, info->type);
    info->len = len;
    info->event_source = event_source(lw_thread); // generic events generated from Go
    info->extra_id = extra_runtime_id();          // required for deleting the trace information
    // also required for deleting the trace information; translated so the
    // delete key matches the (translated) server_traces store key
    pid_key_t self_key = {0};
    task_tid(&self_key);
    java_vt_translate_tid(&self_key);
    info->task_tid = self_key.tid;
}

static __always_inline void process_http_response(http_info_t *info, const unsigned char *buf) {
    info->resp_len = 0;
    info->end_monotime_ns = bpf_ktime_get_ns();
    // An earlier buffer on this connection may have been marked as the response arriving
    // unparsed. This one parsed, so the record carries a status after all.
    info->response_observation = http_response_parsed;

    u16 status = 0;

    status += (buf[RESPONSE_STATUS_POS] - '0') * 100;
    status += (buf[RESPONSE_STATUS_POS + 1] - '0') * 10;
    status += (buf[RESPONSE_STATUS_POS + 2] - '0');

    if (status == 100 || status == 103 || status > MAX_HTTP_STATUS) {
        status = 0;
    }

    info->status = status;
}

static __always_inline void handle_http_response(unsigned char *small_buf,
                                                 pid_connection_info_t *pid_conn,
                                                 http_info_t *info,
                                                 int orig_len,
                                                 lw_thread_t lw_thread) {
    process_http_response(info, small_buf);
    if (info->type == k_event_type_http_request) {
        cleanup_http_server_response_data(pid_conn, info);
    } else {
        delete_client_trace_info(pid_conn);
    }

    // Generic Go events cannot be delayed since we don't probe on net_close.
    // SSL connections must always be delayed: subsequent SSL_read calls deliver
    // the response body (e.g. SSE streaming) and require the request to remain
    // active in ongoing_http.
    if (lw_thread != k_lw_thread_none) {
        finish_http(info, pid_conn, NULL);
        delete_go_trace_info(lw_thread, pid_conn->pid);
        return;
    }

    if (info->type == k_event_type_http_request) {
        info->delayed = 1;
        mark_http_server_thread_trace_response_sent(info);
        if (high_request_volume && !info->ssl) {
            submit_http_event(info);
        }
        return;
    }

    if (high_request_volume && !info->ssl) {
        finish_http(info, pid_conn, NULL);
        return;
    }

    bpf_dbg_printk("Delaying finish http for large request, orig_len=%d", orig_len);
    info->delayed = 1;
}

static __always_inline int http_send_large_buffer(void *ctx,
                                                  http_info_t *req,
                                                  const pid_connection_info_t *pid_conn,
                                                  const void *u_buf,
                                                  u32 bytes_len,
                                                  u8 packet_type,
                                                  u8 direction,
                                                  enum large_buf_action action) {
    const u32 bytes_sent =
        packet_type == PACKET_TYPE_REQUEST ? req->lb_req_bytes : req->lb_res_bytes;

    if (http_max_captured_bytes == 0 || bytes_sent >= http_max_captured_bytes || bytes_len == 0) {
        return 0;
    }

    u32 max_available_bytes = http_max_captured_bytes - bytes_sent;
    bpf_clamp_umax(max_available_bytes, k_large_buf_max_http_captured_bytes);

    large_buf_emit_state_t *state = (large_buf_emit_state_t *)large_buf_emit_state_mem();
    if (!state) {
        return -1;
    }

    state->u_buf = (u64)u_buf;
    state->remaining_bytes = min(bytes_len, max_available_bytes);
    state->pid_conn = *pid_conn;
    state->batch_iter = 0;
    state->packet_type = packet_type;
    state->direction = direction;
    state->action = action;

    preempt_guarded_tail_call_static(ctx, &jump_table, k_tail_large_buf_emit_continue);
    return 0;
}

static __always_inline int __obi_continue2_protocol_http(struct pt_regs *ctx,
                                                         call_protocol_args_t *args,
                                                         http_info_t *info,
                                                         http_connection_metadata_t *meta) {
    // An adopted Java reservation already owns its span. Connection trace state
    // can be replaced or removed on another CPU before this continuation runs.
    if (meta && !valid_span(info->tp.span_id)) {
        const u32 type = trace_type_from_meta(meta);
        tp_info_pid_t *tp_p = trace_info_for_connection(&args->pid_conn.conn, type);
        if (tp_p) {
            info->tp = tp_p->tp;
            if (args->self_ref_parent_id) {
                bpf_dbg_printk("overwriting parent id from the self referencing client request");
                __builtin_memcpy(&info->tp.parent_id, &args->self_ref_parent_id, sizeof(u64));
            }
        } else {
            bpf_dbg_printk("Can't find trace info, this is a bug!");
        }
    } else {
        bpf_dbg_printk("No META!");
    }

    // we copy some small part of the buffer to the info trace event, so that we can process an event even with
    // incomplete trace info in user space.
    read_request_buf(info, args);
    process_http_request(info,
                         args->bytes_len,
                         meta,
                         args->direction,
                         args->orig_dport,
                         args->lw_thread,
                         (struct sock *)args->sock_ptr);

    if (http_server_index_enabled()) {
        index_http_server_trace(&args->pid_conn, info);
    }

    // Emit large buffer last: may tail call for continuation batches, so all
    // critical state updates must precede this call.
    http_send_large_buffer(ctx,
                           info,
                           &args->pid_conn,
                           (void *)args->u_buf,
                           args->bytes_len,
                           args->packet_type,
                           args->direction,
                           k_large_buf_action_init);

    return 0;
}

// k_tail_continue2_protocol_http
SEC("kprobe/http")
int GUARDED_PROG(obi_continue2_protocol_http, struct pt_regs *, ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
    if (!info) {
        return 0;
    }

    http_connection_metadata_t *meta =
        connection_meta_by_direction(args->direction, PACKET_TYPE_REQUEST);

    return __obi_continue2_protocol_http(ctx, args, info, meta);
}

static __always_inline void
commit_http_tp(call_protocol_args_t *args, http_connection_metadata_t *meta, tp_info_pid_t *tp_p) {
    if (!meta) {
        return;
    }

    const u32 type = trace_type_from_meta(meta);
    set_trace_info_for_connection(&args->pid_conn.conn, type, tp_p);
    // TODO: If the user code setup traceparent manually, don't interfere and add
    // something else with TC L7. The main challenge is that with kprobes, the
    // sock_msg program has already punched a hole in the HTTP headers and has made
    // the HTTP header invalid. We need to add more smarts there or pull the
    // sock msg information here and mark it so that we don't override the span_id.
    server_or_client_trace(meta->type,
                           &args->pid_conn.conn,
                           args->lw_thread,
                           tp_p,
                           args->ssl,
                           args->orig_dport,
                           0,
                           BPF_ANY);
}

static __always_inline void resolve_wire_client_parent(call_protocol_args_t *args,
                                                       tp_info_pid_t *tp_p) {
    const u8 status = find_trace_for_wire_client_request(
        &args->pid_conn, args->orig_dport, args->lw_thread, &tp_p->tp);

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
    if (info) {
        info->parent_status = status;
    }
}

// k_tail_continue_protocol_http_tp_commit
SEC("kprobe/http")
int GUARDED_PROG(obi_continue_protocol_http_tp_commit, struct pt_regs *, ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!tp_p) {
        return 0;
    }

    http_connection_metadata_t *meta =
        connection_meta_by_direction(args->direction, PACKET_TYPE_REQUEST);

    if (args->wire_tp_found) {
        resolve_wire_client_parent(args, tp_p);
    }

    commit_http_tp(args, meta, tp_p);

    preempt_guarded_tail_call(ctx, &jump_table, k_tail_continue2_protocol_http);
    return 0;
}

// Returns true for a client's own traceparent: the library chose the client
// span, and its parent still needs find_trace_for_wire_client_request.
static __always_inline bool
inherit_http1_traceparent(tp_info_t *tp, unsigned char *header, u8 type) {
    decode_hex(tp->trace_id, extract_trace_id(header), TRACE_ID_CHAR_LEN);
    decode_hex(&tp->flags, extract_flags(header), FLAGS_CHAR_LEN);

    if (type == k_event_type_http_client) {
        decode_hex(tp->span_id, extract_span_id(header), SPAN_ID_CHAR_LEN);
        return true;
    }

    if (type) {
        decode_hex(tp->parent_id, extract_span_id(header), SPAN_ID_CHAR_LEN);
        sample_remote_child(tp);
    }

    return false;
}

static __always_inline bool
same_http1_span(const unsigned char *trace_id, const unsigned char *span_id, const tp_info_t *tp) {
    return bpf_memcmp(trace_id, tp->trace_id, TRACE_ID_SIZE_BYTES) == 0 &&
           bpf_memcmp(span_id, tp->span_id, SPAN_ID_SIZE_BYTES) == 0;
}

static __always_inline tp_info_pid_t *http1_server_aux_trace(const call_protocol_args_t *args,
                                                             const http_info_t *info) {
    connection_info_part_t part = {};
    populate_ephemeral_info(
        &part, &args->pid_conn.conn, args->orig_dport, args->pid_conn.pid, FD_SERVER);

    tp_info_pid_t *aux = bpf_map_lookup_elem(&server_traces_aux, &part);
    if (aux && same_http1_span(aux->tp.trace_id, aux->tp.span_id, &info->tp)) {
        return aux;
    }

    return NULL;
}

static __always_inline tp_info_t *http1_server_goroutine_trace(const call_protocol_args_t *args,
                                                               const http_info_t *info) {
    if (args->lw_thread == k_lw_thread_none) {
        return NULL;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id_and_pid(
        &g_key, (void *)args->lw_thread, pid_from_pid_tgid(bpf_get_current_pid_tgid()));

    tp_info_t *goroutine_tp = bpf_map_lookup_elem(&go_trace_map, &g_key);
    if (goroutine_tp && same_http1_span(goroutine_tp->trace_id, goroutine_tp->span_id, &info->tp)) {
        return goroutine_tp;
    }

    return NULL;
}

// Request buffers already sent to userspace are keyed by the trace and span they
// went out with: move them to the inherited ones, otherwise the request gets split.
// This will happen if we got partial HTTP buffer, decided to start a request and got
// our own trace id, but then by scanning further packets we found an incoming trace.
static __always_inline void http_rekey_request_large_buffer(const http_info_t *info,
                                                            u8 direction,
                                                            const unsigned char *previous_trace_id,
                                                            const unsigned char *previous_span_id) {
    if (!info->lb_req_bytes || same_http1_span(previous_trace_id, previous_span_id, &info->tp)) {
        return;
    }

    bpf_d_printk("rekeying large request buffers, lb_req_bytes=%d", info->lb_req_bytes);

    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)tcp_large_buffers_mem();
    if (!large_buf) {
        return;
    }

    large_buf->type = k_event_type_tcp_large_buffer;
    large_buf->packet_type = PACKET_TYPE_REQUEST;
    large_buf->direction = direction;
    large_buf->conn_info = info->conn_info;
    large_buf->action = k_large_buf_action_rekey;
    large_buf->kind = k_large_buf_layer_app;
    large_buf->tp = info->tp;
    large_buf->source = k_large_buffer_source_kprobes;
    large_buf->len = TRACE_ID_SIZE_BYTES + SPAN_ID_SIZE_BYTES;
    __builtin_memcpy(large_buf->buf, previous_trace_id, TRACE_ID_SIZE_BYTES);
    __builtin_memcpy(large_buf->buf + TRACE_ID_SIZE_BYTES, previous_span_id, SPAN_ID_SIZE_BYTES);

    events_ringbuf_output(large_buf, sizeof(*large_buf) + TRACE_ID_SIZE_BYTES + SPAN_ID_SIZE_BYTES);
}

static __always_inline void set_http1_connection_trace(const call_protocol_args_t *args,
                                                       const http_info_t *info,
                                                       u8 trace_type) {
    const tp_info_pid_t trace = {
        .tp = info->tp,
        .pid = args->pid_conn.pid,
        .valid = 1,
        .req_type = info->type,
    };

    set_trace_info_for_connection(&args->pid_conn.conn, trace_type, &trace);
}

// The server's thread, aux and goroutine traces, and its index entry, still
// carry the trace the request started with.
static __always_inline void inherit_http1_server_traceparent(const call_protocol_args_t *args,
                                                             http_info_t *info,
                                                             unsigned char *header) {
    trace_key_t owner_key = {};
    tp_info_pid_t *owner = http_server_thread_trace(info, &owner_key);
    tp_info_pid_t *aux = http1_server_aux_trace(args, info);
    tp_info_t *goroutine_tp = http1_server_goroutine_trace(args, info);
    unsigned char previous_trace_id[TRACE_ID_SIZE_BYTES];
    __builtin_memcpy(previous_trace_id, info->tp.trace_id, sizeof(previous_trace_id));

    inherit_http1_traceparent(&info->tp, header, info->type);
    bpf_d_printk("server inherits late traceparent, owner=%d, aux=%d, goroutine=%d",
                 owner != NULL,
                 aux != NULL,
                 goroutine_tp != NULL);

    if (owner) {
        owner->tp = info->tp;
    }

    if (aux) {
        aux->tp = info->tp;
    }

    if (goroutine_tp) {
        *goroutine_tp = info->tp;
    }

    if (http_server_index_enabled()) {
        unindex_http_server_trace_id(args->pid_conn.pid, previous_trace_id, info->tp.span_id);
        index_http_server_trace(&args->pid_conn, info);
    }

    set_http1_connection_trace(args, info, TRACE_TYPE_SERVER);
}

// update_http1_request_context handles the replacement of the trace context of a late
// discovery of a traceparent in the header buffers of an incoming request.
static __always_inline void
update_http1_request_context(call_protocol_args_t *args, http_info_t *info, unsigned char *header) {
    const u64 id = bpf_get_current_pid_tgid();
    const obi_ctx_info_t *context = obi_ctx__get(id);
    const bool owns_context =
        context && same_http1_span(context->trace_id, context->span_id, &info->tp);
    unsigned char previous_trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char previous_span_id[SPAN_ID_SIZE_BYTES];
    __builtin_memcpy(previous_trace_id, info->tp.trace_id, sizeof(previous_trace_id));
    __builtin_memcpy(previous_span_id, info->tp.span_id, sizeof(previous_span_id));

    inherit_http1_server_traceparent(args, info, header);

    if (owns_context) {
        obi_ctx__set(id, &info->tp);
    }

    http_rekey_request_large_buffer(info, args->direction, previous_trace_id, previous_span_id);
}

// A kprobe copies at most k_iovec_max_len bytes of a read or write into u_buf:
// past that, the headers are read from the user buffer itself.
static __always_inline void read_http1_request_headers(http1_header_scan_t *scan,
                                                       const call_protocol_args_t *args) {
    const bool truncated = args->user_buf != 0;
    const unsigned char *src = (const unsigned char *)(truncated ? args->user_buf : args->u_buf);
    const u32 len = truncated ? args->user_len : (u32)args->bytes_len;
    if (truncated) {
        bpf_d_printk("reading headers past the copy, copied=%d, len=%d", args->bytes_len, len);
    }

    http1_read_headers(scan, src, len, k_http1_memory_any);
    bpf_d_printk("read headers len=%d, valid=%d, found=%d", len, scan->valid, scan->present);
}

static __always_inline bool http1_traceparent_usable(const http1_header_scan_t *scan) {
    return scan->phase == k_http1_headers_done && scan->present && scan->valid;
}

// Returns true when the headers end with a traceparent to adopt. The scan then
// stays stored for obi_protocol_http_inherit_tp, which adopts it.
static __always_inline bool continue_http1_header_scan(const call_protocol_args_t *args,
                                                       http1_header_scan_t *scan) {
    read_http1_request_headers(scan, args);
    if (scan->phase != k_http1_headers_done) {
        return false;
    }

    if (http1_traceparent_usable(scan)) {
        bpf_d_printk("late traceparent found, bytes=%d", scan->bytes);
        return true;
    }

    bpf_map_delete_elem(&http1_header_scans, &args->pid_conn);
    return false;
}

static __always_inline int
append_http1_request_buffer(void *ctx, const call_protocol_args_t *args, http_info_t *info) {
    info->len += args->bytes_len;
    return http_send_large_buffer(ctx,
                                  info,
                                  &args->pid_conn,
                                  (void *)args->u_buf,
                                  args->bytes_len,
                                  PACKET_TYPE_REQUEST,
                                  args->direction,
                                  k_large_buf_action_append);
}

// k_tail_protocol_http_inherit_tp
SEC("kprobe/http")
int GUARDED_PROG(obi_protocol_http_inherit_tp, void *, ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
    http1_header_scan_t *scan = bpf_map_lookup_elem(&http1_header_scans, &args->pid_conn);
    if (info && scan) {
        update_http1_request_context(args, info, scan->header);
    }

    bpf_map_delete_elem(&http1_header_scans, &args->pid_conn);

    return info ? append_http1_request_buffer(ctx, args, info) : 0;
}

// Only a scan that the following buffers of the request must finish is
// stored, so headers that end in the first buffer cost no map update.
static __always_inline unsigned char *start_http1_header_scan(const call_protocol_args_t *args) {
    http1_header_scan_t *scan = http1_header_scan_mem();
    if (!scan) {
        return NULL;
    }

    __builtin_memset(scan, 0, sizeof(*scan));
    read_http1_request_headers(scan, args);

    if (scan->phase != k_http1_headers_done) {
        bpf_d_printk(
            "headers continue in the next buffer, phase=%d, bytes=%d", scan->phase, scan->bytes);
        bpf_map_update_elem(&http1_header_scans, &args->pid_conn, scan, BPF_ANY);
        return NULL;
    }

    return http1_traceparent_usable(scan) ? scan->header : NULL;
}

static __always_inline int __obi_continue_protocol_http_tp(struct pt_regs *ctx,
                                                           call_protocol_args_t *args,
                                                           http_info_t *info,
                                                           http_connection_metadata_t *meta,
                                                           bool use_bpf_loop) {
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!tp_p) {
        goto done;
    }

    if (g_bpf_traceparent_enabled && !args->skip_tp_parsing) {
        // The below buffer scan can be expensive on high volume of requests. We make it optional
        // for customers to enable it. Off by default.
        if (!capture_header_buffer) {
            if (meta) {
                tp_p->tp.ts = bpf_ktime_get_ns();
                tp_p->valid = 1;
                tp_p->pid = args->pid_conn.pid;
                tp_p->req_type = meta->type;
                const u32 type = trace_type_from_meta(meta);
                set_trace_info_for_connection(&args->pid_conn.conn, type, tp_p);
                server_or_client_trace(meta->type,
                                       &args->pid_conn.conn,
                                       args->lw_thread,
                                       tp_p,
                                       args->ssl,
                                       args->orig_dport,
                                       0,
                                       BPF_ANY);
            }
            goto done;
        }

        // Outgoing requests are scanned only in their first TRACE_BUF_SIZE bytes,
        // see "HTTP/1 header scan window" in devdocs/context-propagation.md.
        const bool incoming = meta && meta->type == k_event_type_http_request;
        unsigned char *res = NULL;
        if (use_bpf_loop && incoming) {
            res = start_http1_header_scan(args);
        } else {
            unsigned char *buf = tp_char_buf_mem();
            if (!buf) {
                goto done;
            }
            u16 buf_len = args->bytes_len;
            bpf_clamp_umax(buf_len, TRACE_BUF_SIZE - 1);

            bpf_probe_read(buf, buf_len, (void *)args->u_buf);
            // null terminate to make proper string
            buf[buf_len] = '\0';

            if (use_bpf_loop) {
                res = bpf_strstr_tp_loop(buf, buf_len);
            } else {
                res = bpf_strstr_tp_loop__legacy(buf, buf_len);
            }
        }

        if (res) {
            args->wire_tp_found = inherit_http1_traceparent(&tp_p->tp, res, meta ? meta->type : 0);
        }
    }

    // The legacy scan forks a verifier state per offset it can match at, the tail
    // call keeps those states from also exploring the trace bookkeeping. A client
    // traceparent needs a second parent search, which stays out of this program too.
    if (!use_bpf_loop || args->wire_tp_found) {
        preempt_guarded_tail_call(ctx, &jump_table, k_tail_continue_protocol_http_tp_commit);
        return 0;
    }

    commit_http_tp(args, meta, tp_p);

done:
    if (use_bpf_loop) {
        return __obi_continue2_protocol_http(ctx, args, info, meta);
    } else {
        preempt_guarded_tail_call(ctx, &jump_table, k_tail_continue2_protocol_http);
        return 0;
    }
}

// k_tail_continue_protocol_http_tp
SEC("kprobe/http")
int GUARDED_PROG(obi_continue_protocol_http_tp, struct pt_regs *, ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
    if (!info) {
        return 0;
    }

    http_connection_metadata_t *meta =
        connection_meta_by_direction(args->direction, PACKET_TYPE_REQUEST);

    return __obi_continue_protocol_http_tp(ctx, args, info, meta, false);
}

static __always_inline bool adopt_java_http1_reservation(call_protocol_args_t *args,
                                                         http_info_t *info,
                                                         const http_connection_metadata_t *meta) {
    if (!g_bpf_java_http1_enabled || !g_bpf_header_propagation || !args->ssl || !meta ||
        meta->type != k_event_type_http_client) {
        return false;
    }

    const u64 request_id = java_http1_request_id(&args->pid_conn);
    java_http1_request_t *reservation = java_http1_request_lookup(&args->pid_conn, request_id);
    unsigned char *scratch = tp_char_buf_mem();
    if (!reservation || !scratch) {
        return false;
    }

    const u32 offset = reservation->data.value_offset;
    if (args->bytes_len < TP_MAX_VAL_LENGTH || offset > args->bytes_len - TP_MAX_VAL_LENGTH) {
        return false;
    }
    unsigned char *reserved_traceparent = scratch;
    unsigned char *plaintext_traceparent = scratch + TP_MAX_VAL_LENGTH;
    if (bpf_probe_read_user(plaintext_traceparent,
                            TP_MAX_VAL_LENGTH,
                            (const unsigned char *)args->u_buf + offset) != 0) {
        return false;
    }
    make_tp_string(reserved_traceparent, &reservation->data.tp.tp);
    if (bpf_memcmp(reserved_traceparent, plaintext_traceparent, TP_MAX_VAL_LENGTH) != 0) {
        return false;
    }

    // Copy before retirement can free the slot. A successful claim proves this
    // generation stayed live throughout the copy and the plaintext comparison.
    tp_info_pid_t client_span = reservation->data.tp;
    const u8 parent_status = reservation->data.parent_status;
    if (!java_http1_request_retire(&args->pid_conn, reservation, request_id)) {
        return false;
    }
    set_trace_info_for_connection(&args->pid_conn.conn, TRACE_TYPE_CLIENT, &client_span);
    info->tp = client_span.tp;
    info->parent_status = parent_status;
    server_or_client_trace(meta->type,
                           &args->pid_conn.conn,
                           args->lw_thread,
                           &client_span,
                           args->ssl,
                           args->orig_dport,
                           0,
                           BPF_ANY);
    return true;
}

static __always_inline int __obi_continue_protocol_http(struct pt_regs *ctx,
                                                        call_protocol_args_t *args,
                                                        http_info_t *info,
                                                        bool use_bpf_loop) {
    http_connection_metadata_t *meta =
        connection_meta_by_direction(args->direction, PACKET_TYPE_REQUEST);

    args->wire_tp_found = 0;
    if (adopt_java_http1_reservation(args, info, meta)) {
        goto skip_tp;
    }

    egress_key_t e_key = {
        .d_port = args->pid_conn.conn.d_port,
        .s_port = args->pid_conn.conn.s_port,
    };

    sort_egress_key(&e_key);

    tp_info_pid_t *tp_p = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);

    if (tp_p && tp_p->req_type == k_event_type_http_client && tp_p->written &&
        tp_p->pid == args->pid_conn.pid) {
        bpf_dbg_printk("found tp info previously set by sock msg");
        // we've already got a tp_info_pid_t setup by the sockmsg program, use
        // that instead
        set_trace_info_for_connection(&args->pid_conn.conn, TRACE_TYPE_CLIENT, tp_p);
        // clean up so that TC does not pick it up
        bpf_map_delete_elem(&outgoing_trace_map, &e_key);
        goto skip_tp;
    }

    tp_p = (tp_info_pid_t *)tp_info_mem();

    if (!tp_p) {
        goto skip_tp;
    }

    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->written = 0;
    tp_p->pid = args->pid_conn
                    .pid; // used for avoiding finding stale server requests with client port reuse
    tp_p->req_type = (meta) ? meta->type : 0;

    urand_bytes(tp_p->tp.span_id, SPAN_ID_SIZE_BYTES);

    u8 found_tp = 0;

    if (meta) {
        if (meta->type == k_event_type_http_client) {
            pid_connection_info_t p_conn = {.pid = args->pid_conn.pid};
            __builtin_memcpy(&p_conn.conn, &args->pid_conn.conn, sizeof(connection_info_t));
            found_tp = find_trace_for_client_request(
                &p_conn, args->orig_dport, args->lw_thread, &tp_p->tp);
            info->parent_status = found_tp;
        } else {
            //bpf_dbg_printk("Looking up existing trace for connection");
            //dbg_print_http_connection_info(conn);

            // For server requests, we first look for TCP info (setup by TC ingress) and then we fall back to black-box info.
            found_tp = find_trace_for_server_request(
                &args->pid_conn.conn, &tp_p->tp, k_event_type_http_request);
            if (found_tp) {
                sample_remote_child(&tp_p->tp);
            }
        }
    }

    if (!found_tp) {
        bpf_dbg_printk("Generating new traceparent id");
        new_trace_id(&tp_p->tp);
        __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
        sample_new_trace(&tp_p->tp);
    } else {
        bpf_dbg_printk("Using old traceparent id");
    }

    if (g_bpf_debug) {
        unsigned char tp_buf[TP_MAX_VAL_LENGTH];
        make_tp_string(tp_buf, &tp_p->tp);
        bpf_dbg_printk("tp: %s", tp_buf);
    }

    args->skip_tp_parsing = 0;

    // If we receive SSL request, we know that OBI definitely didn't
    // inject the traceparent via the header, so if we already have
    // info about this transaction keep that, don't parse headers. Istio
    // for example can forward headers as-is, which can give us a stale
    // value.
    if (meta) {
        if (meta->type == k_event_type_http_request && found_tp && args->ssl) {
            bpf_dbg_printk("skipping headers parsing because of existing tp info for SSL call");
            args->skip_tp_parsing = 1;
        }
    }

    if (use_bpf_loop) {
        return __obi_continue_protocol_http_tp(ctx, args, info, meta, true);
    } else {
        preempt_guarded_tail_call(ctx, &jump_table, k_tail_continue_protocol_http_tp);
        return 0;
    }

skip_tp:
    if (use_bpf_loop) {
        return __obi_continue2_protocol_http(ctx, args, info, meta);
    } else {
        preempt_guarded_tail_call(ctx, &jump_table, k_tail_continue2_protocol_http);
        return 0;
    }
}

// k_tail_continue_protocol_http (legacy)
SEC("kprobe/http")
int GUARDED_PROG(obi_continue_protocol_http_legacy, struct pt_regs *, ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
    if (!info) {
        return 0;
    }

    return __obi_continue_protocol_http(ctx, args, info, false);
}

// k_tail_continue_protocol_http (new kernels)
SEC("kprobe/http")
int GUARDED_PROG(obi_continue_protocol_http, struct pt_regs *, ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
    if (!info) {
        return 0;
    }

    if (args->use_bpf_loop) {
        return __obi_continue_protocol_http(ctx, args, info, true);
    }

    return __obi_continue_protocol_http(ctx, args, info, false);
}

static __always_inline int __obi_protocol_http(struct pt_regs *ctx, bool use_bpf_loop) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    http_info_t *in = empty_http_info();
    if (!in) {
        bpf_dbg_printk("Error allocating http info from per CPU map");
        return 0;
    }

    __builtin_memcpy(&in->conn_info, &args->pid_conn.conn, sizeof(connection_info_t));
    in->ssl = args->ssl;

    // If we have the same process (or even thread) call itself through HTTP, the
    // connection information is identical. This means that the client call information
    // will be overwritten by the server call. In this situation we'll create a gap in
    // the trace propagation chain, e.g. the client span is lost. To mitigate this edge
    // case, we pick out the parent_id of the self referencing client call before the
    // request is overwritten and later we overwrite the client set parent with the
    // original one that was set on the client call itself.
    u64 self_ref_parent_id = 0;
    tp_info_t *self_ref_tp = self_referencing_request(&args->pid_conn, args->packet_type);
    if (self_ref_tp) {
        __builtin_memcpy(&self_ref_parent_id, &self_ref_tp->parent_id, sizeof(u64));
    }
    args->self_ref_parent_id = self_ref_parent_id;

    http_info_t *info = get_or_set_http_info(
        in, &args->pid_conn, args->packet_type, args->direction, (struct sock *)args->sock_ptr);
    if (!info) {
        bpf_dbg_printk("No info (or duplicate), pid=%d?", args->pid_conn.pid);
        dbg_print_http_connection_info(&args->pid_conn.conn);
        return 0;
    }

    bpf_dbg_printk("=== kprobe/http http_buffer_event: len=%d, pid=%d, still_reading=%d ===",
                   args->bytes_len,
                   pid_from_pid_tgid(bpf_get_current_pid_tgid()),
                   still_reading(info));

    info->direction = args->direction;
    if (args->packet_type == PACKET_TYPE_REQUEST && (info->status == 0) &&
        (info->start_monotime_ns == 0)) {

        args->use_bpf_loop = use_bpf_loop;
        preempt_guarded_tail_call(ctx, &jump_table, k_tail_continue_protocol_http);

        return 0;
    } else if ((args->packet_type == PACKET_TYPE_RESPONSE) && (info->status == 0)) {
        handle_http_response(
            args->small_buf, &args->pid_conn, info, args->bytes_len, args->lw_thread);
        http_send_large_buffer(ctx,
                               info,
                               &args->pid_conn,
                               (void *)args->u_buf,
                               args->bytes_len,
                               args->packet_type,
                               args->direction,
                               k_large_buf_action_init);
    } else if (still_reading(info)) {
        // print here
        info->len += args->bytes_len;
        http_send_large_buffer(ctx,
                               info,
                               &args->pid_conn,
                               (void *)args->u_buf,
                               args->bytes_len,
                               args->packet_type,
                               args->direction,
                               k_large_buf_action_append);
    } else if (still_responding(info)) {
        info->end_monotime_ns = bpf_ktime_get_ns();
        info->resp_len += args->bytes_len;
        http_send_large_buffer(ctx,
                               info,
                               &args->pid_conn,
                               (void *)args->u_buf,
                               args->bytes_len,
                               PACKET_TYPE_RESPONSE,
                               args->direction,
                               k_large_buf_action_append);
    }

    return 0;
}

// k_tail_protocol_http
SEC("kprobe/http")
int GUARDED_PROG(obi_protocol_http, struct pt_regs *, ctx) {
    return __obi_protocol_http(ctx, true);
}

// k_tail_protocol_http
SEC("kprobe/http")
int GUARDED_PROG(obi_protocol_http_legacy, struct pt_regs *, ctx) {
    return __obi_protocol_http(ctx, false);
}

// k_tail_large_buf_emit_continue
SEC("kprobe/http")
int GUARDED_PROG(obi_large_buf_emit_continue, struct pt_regs *, ctx) {
    large_buf_emit_state_t *state = (large_buf_emit_state_t *)large_buf_emit_state_mem();
    if (!state || state->remaining_bytes == 0) {
        return 0;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &state->pid_conn);
    if (!info) {
        return 0;
    }

    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)tcp_large_buffers_mem();
    if (!large_buf) {
        return 0;
    }

    large_buf->type = k_event_type_tcp_large_buffer;
    large_buf->packet_type = state->packet_type;
    large_buf->direction = state->direction;
    large_buf->conn_info = info->conn_info;
    large_buf->action = state->batch_iter == 0 ? state->action : k_large_buf_action_append;
    large_buf->kind = k_large_buf_layer_app;
    large_buf->tp = info->tp;
    large_buf->source = k_large_buffer_source_kprobes;

    const u32 consumed_bytes = large_buf_emit_chunks(
        large_buf, (const void *)state->u_buf, state->remaining_bytes, k_large_buf_read_kernel);

    if (consumed_bytes > 0) {
        info->has_large_buffers = true;
        if (state->packet_type == PACKET_TYPE_REQUEST) {
            info->lb_req_bytes += consumed_bytes;
        } else {
            info->lb_res_bytes += consumed_bytes;
        }
    }

    state->u_buf += consumed_bytes;
    state->remaining_bytes -= consumed_bytes;
    state->batch_iter++;

    if (state->remaining_bytes > 0 && consumed_bytes > 0 &&
        state->batch_iter < k_large_buf_max_batches) {
        preempt_guarded_tail_call_static(ctx, &jump_table, k_tail_large_buf_emit_continue);
    }

    return 0;
}
