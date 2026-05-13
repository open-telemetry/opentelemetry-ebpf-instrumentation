// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/connection_info.h>
#include <common/event_defs.h>
#include <common/http_types.h>
#include <common/large_buffers.h>
#include <common/lw_thread.h>
#include <common/ringbuf.h>
#include <common/runtime.h>
#include <common/scratch_mem.h>
#include <common/trace_helpers.h>
#include <common/trace_lifecycle.h>
#include <common/trace_parent.h>
#include <common/tracked_connection.h>

#include <generictracer/maps/http_info_mem.h>

#include <generictracer/k_tracer_tailcall.h>
#include <generictracer/large_buf_tailcall.h>
#include <generictracer/protocol_common.h>

#include <logger/bpf_dbg.h>

#include <maps/active_ssl_connections.h>
#include <maps/connection_tracker.h>
#include <maps/ongoing_http.h>
#include <maps/tp_info_mem.h>
#include <maps/tp_char_buf_mem.h>

volatile const u32 high_request_volume;

SCRATCH_MEM_SIZED(http_previous_trace_id, TRACE_ID_SIZE_BYTES);

// Tail-call budget analysis:
//
// Non-append path (initial request parse):
//   3 preamble tail-calls (handle_buf_with_args → protocol_http → continue_protocol_http)
//   + 28 chunk iterations (niter 1..28; chunk 0 is scanned inline in
//   __obi_continue_protocol_http_tp before the first tail-call to this program)
//   = 31 ≤ BPF_MAX_TAIL_CALL_CNT (32 on kernels 5.8–5.9, 33 on 5.10+).
//
// Append path (large-buffer still_reading / obi_handle_buf_with_args):
//   1 preamble tail-call (handle_buf_with_args) + 29 chunk iterations (niter 0..28)
//   = 30 ≤ 32.
//
// k_tp_chunk_step overlaps by TRACE_PARENT_HEADER_LEN so a header straddling a chunk
// boundary is always fully contained in at least one chunk. The last iteration (niter=28)
// starts at offset 26,768 and covers up to 27,792 bytes (27 KB maximum).
enum {
    k_tp_parse_max_niter = 29,
    k_tp_chunk_step = TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN,
};

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
    if (meta->type == EVENT_HTTP_CLIENT) {
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

static __always_inline bool still_responding(http_info_t *info) {
    return info->status != 0;
}

static __always_inline bool still_reading(http_info_t *info) {
    return info->status == 0 && info->start_monotime_ns != 0;
}

static __always_inline u8 http_info_complete(http_info_t *info) {
    return (info->start_monotime_ns != 0 && info->status != 0 && info->pid.host_pid != 0);
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

static __always_inline void finish_http(http_info_t *info, pid_connection_info_t *pid_conn) {
    if (http_info_complete(info) && !info->submitted) {
        info->submitted = 1;
        bpf_map_update_elem(&ongoing_http, pid_conn, info, BPF_ANY);
        http_info_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_info_t), 0);
        if (trace) {
            bpf_dbg_printk("Sending trace %lx, response length %d", info, info->resp_len);

            __builtin_memcpy(trace, info, sizeof(http_info_t));
            trace->flags = EVENT_K_HTTP_REQUEST;
            bpf_ringbuf_submit(trace, get_flags());
        } else {
            bpf_dbg_printk("failed to reserve space in the ringbuf");
        }

        // bpf_dbg_printk("Terminating trace for pid=%d", pid_from_pid_tgid(pid_tid));
        // dbg_print_http_connection_info(&info->conn_info); // commented out since GitHub CI doesn't like this call
        // Don't delete requests that weren't delayed, we might be receiving still more packets, for
        // example SSL.
        if (info->delayed) {
            bpf_map_delete_elem(&ongoing_http, pid_conn);
        }

        bpf_map_delete_elem(&active_ssl_connections, pid_conn);
    }
}

static __always_inline void force_finish_http(http_info_t *info, pid_connection_info_t *pid_conn) {
    if (info->submitted) {
        return;
    }

    if (!high_request_volume) {
        if (!http_info_complete(info)) {
            info->resp_len = 0;
            info->end_monotime_ns = bpf_ktime_get_ns();
            info->status = 499;
        }
    }

    finish_http(info, pid_conn);
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
                                                         u8 direction) {
    if (packet_type == PACKET_TYPE_REQUEST) {
        http_info_t *old_info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
        if (old_info && !old_info->submitted) {
            const u8 req_type = request_type_by_direction(direction, packet_type);
            if (!http_info_complete(old_info)) {
                if (old_info->type == req_type && is_duplicate_info(old_info)) {
                    return 0;
                }
            }
            // this will delete ongoing_http for this connection info if there's full stale request
            finish_http(old_info, pid_conn);
        }

        bpf_map_update_elem(&ongoing_http, pid_conn, info, BPF_ANY);
    }

    return bpf_map_lookup_elem(&ongoing_http, pid_conn);
}

static __always_inline tp_info_t *self_referencing_request(pid_connection_info_t *pid_conn,
                                                           u8 packet_type) {
    if (packet_type == PACKET_TYPE_REQUEST) {
        http_info_t *old_info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
        if (old_info && !http_info_complete(old_info) && old_info->type == EVENT_HTTP_CLIENT) {
            bpf_dbg_printk("found self referencing request, remembering the old tp info parent_id");
            return &old_info->tp;
        }
    }

    return 0;
}

static __always_inline void finish_possible_delayed_http_request(pid_connection_info_t *pid_conn) {
    if (high_request_volume) {
        return;
    }
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info && info->delayed) {
        finish_http(info, pid_conn);
    }
}

static __always_inline void
force_finish_possible_delayed_http_request(pid_connection_info_t *pid_conn) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info) {
        if (info->delayed) {
            finish_http(info, pid_conn);
        } else {
            bpf_dbg_printk("forcing HTTP event finish");
            force_finish_http(info, pid_conn);
        }
    }
    cleanup_http_info(pid_conn);
}

static __always_inline void cleanup_http_request_data(pid_connection_info_t *pid_conn,
                                                      http_info_t *info) {
    if (info) {
        if (info->type == EVENT_HTTP_REQUEST) {
            trace_key_t t_key = {0};
            t_key.extra_id = info->extra_id;
            t_key.p_key.ns = info->pid.ns;
            t_key.p_key.tid = info->task_tid;
            t_key.p_key.pid = info->pid.user_pid;
            delete_server_trace(pid_conn, &t_key);
        } else {
            delete_client_trace_info(pid_conn);
        }
    }
}

static __always_inline void terminate_http_request_if_needed(pid_connection_info_t *pid_conn) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    cleanup_http_request_data(pid_conn, info);
    bpf_map_delete_elem(&active_ssl_connections, pid_conn);
}

static __always_inline void process_http_request(http_info_t *info,
                                                 int len,
                                                 http_connection_metadata_t *meta,
                                                 int direction,
                                                 u16 orig_dport,
                                                 lw_thread_t lw_thread) {
    // Set pid and type early as best effort in case the request times out or dies.
    if (meta) {
        info->pid = meta->pid;
        info->type = meta->type;
    } else {
        if (direction == TCP_RECV) {
            info->type = EVENT_HTTP_REQUEST;
        } else {
            info->type = EVENT_HTTP_CLIENT;
        }
        task_pid(&info->pid);
    }

    fixup_connection_info(&info->conn_info, info->type == EVENT_HTTP_CLIENT, orig_dport);

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
            if (info->type == EVENT_HTTP_CLIENT) {
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
    cleanup_http_request_data(pid_conn, info);

    // Generic Go events cannot be delayed since we don't probe on net_close.
    // SSL connections must always be delayed: subsequent SSL_read calls deliver
    // the response body (e.g. SSE streaming) and require the request to remain
    // active in ongoing_http.
    if ((high_request_volume && !info->ssl) || (lw_thread != k_lw_thread_none)) {
        finish_http(info, pid_conn);
        // If we are terminating because of a light weight thread, e.g. Go we must clean
        // the server information we have encoded in the Go structs.
        if (lw_thread != k_lw_thread_none) {
            delete_go_trace_info(lw_thread, pid_conn->pid);
        }
    } else {
        bpf_dbg_printk("Delaying finish http for large request, orig_len=%d", orig_len);
        info->delayed = 1;
    }
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

    bpf_tail_call_static(ctx, &jump_table, k_tail_large_buf_emit_continue);
    return 0;
}

static __always_inline int __obi_continue2_protocol_http(struct pt_regs *ctx,
                                                         call_protocol_args_t *args,
                                                         http_info_t *info,
                                                         http_connection_metadata_t *meta) {
    if (meta) {
        const u32 type = trace_type_from_meta(meta);
        tp_info_pid_t *tp_p = trace_info_for_connection(&args->pid_conn.conn, type);
        if (tp_p) {
            info->tp = tp_p->tp;
            const u64 *orig_id = (const u64 *)info->original_trace_id;
            if (orig_id[0] == 0 && orig_id[1] == 0) {
                // Initialize original_trace_id exactly once per request.
                // W3C trace IDs of all-zeros are invalid and never generated by OBI,
                // so a zero value reliably indicates the field has not been set yet.
                __builtin_memcpy(
                    info->original_trace_id, tp_p->tp.trace_id, sizeof(info->original_trace_id));
            }
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
    bpf_probe_read(info->buf, FULL_BUF_SIZE, (void *)args->u_buf);
    process_http_request(
        info, args->bytes_len, meta, args->direction, args->orig_dport, args->lw_thread);

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
int obi_continue2_protocol_http(struct pt_regs *ctx) {
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

volatile const u32 bpf_max_request_tp_parse_size_kb;

// k_tail_parse_traceparent_http
// jump_table is populated at runtime by Go, so bpf_tail_call_static cannot be used here.
SEC("kprobe/http")
int obi_parse_traceparent_http(struct pt_regs *ctx) {
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
    if (!meta) {
        if (!args->is_append) {
            bpf_tail_call(ctx, &jump_table, k_tail_continue2_protocol_http);
        } else {
            // In append mode, info->len was already updated by the caller.
            // The trace info is unavailable here; emit the large buffer as-is.
            http_send_large_buffer(ctx,
                                   info,
                                   &args->pid_conn,
                                   (void *)args->u_buf,
                                   args->bytes_len,
                                   args->packet_type,
                                   args->direction,
                                   k_large_buf_action_append);
        }
        return 0;
    }

    const u32 type = trace_type_from_meta(meta);
    tp_info_pid_t *tp_p;
    if (args->is_append) {
        // Append path: called from still_reading / obi_handle_buf_with_args.
        // set_trace_info_for_connection was already called during initial request
        // processing, so the trace_map is populated.
        tp_p = trace_info_for_connection(&args->pid_conn.conn, type);
    } else {
        // Non-append path: tail-called from __obi_continue_protocol_http_tp
        // *before* set_trace_info_for_connection is called. The per-CPU scratch
        // tp_info_mem() still holds the tp_info_pid_t populated by
        // __obi_continue_protocol_http and is stable across the tail-call chain.
        tp_p = (tp_info_pid_t *)tp_info_mem();
    }
    if (!tp_p) {
        bpf_dbg_printk(
            "obi_parse_traceparent_http: tp_info_mem() returned NULL, skipping chunked scan");
        goto done;
    }

    unsigned char *buf = (unsigned char *)tp_char_buf_mem();
    if (!buf) {
        goto done_with_trace;
    }

    const u32 chunk_size = k_tp_chunk_step;
    const u32 max_bytes = (u32)bpf_max_request_tp_parse_size_kb * 1024;
    // In append mode, the caller already updated info->len before the tail-call,
    // so base_offset = cumulative bytes processed before this chunk.
    const u32 base_offset = args->is_append ? (u32)(info->len - (u32)args->bytes_len) : 0;
    u32 offset = args->niter * chunk_size;

    if (args->niter >= k_tp_parse_max_niter || (base_offset + offset) >= max_bytes) {
        goto done_with_trace;
    }

    // Use full_bytes_len when we have orig_buf (direct userspace reads beyond iovec buffer)
    const bool use_orig = args->orig_buf && args->full_bytes_len > (u32)args->bytes_len;
    bool read_user = args->u_buf_is_user;
    u32 effective_len = (u32)args->bytes_len;
    u64 read_base = args->u_buf;
    if (use_orig) {
        effective_len = args->full_bytes_len;
        read_base = args->orig_buf;
        read_user = true;
    }

    if (offset >= effective_len) {
        goto done_with_trace;
    }

    u32 to_read = effective_len - offset;
    if (to_read > TRACE_BUF_SIZE) {
        to_read = TRACE_BUF_SIZE;
    }
    // Clamp to_read so the read window does not extend past max_bytes.
    const u32 remaining_budget =
        max_bytes > (base_offset + offset) ? max_bytes - (base_offset + offset) : 0;
    if (to_read > remaining_budget) {
        to_read = remaining_budget;
    }
    if (to_read == 0) {
        goto done_with_trace;
    }
    u32 buf_len = to_read;
    bpf_clamp_umax(buf_len, TRACE_BUF_SIZE);

    _Static_assert(TRACE_BUF_SIZE == 1024,
                   "Please fix the __bpf_memzero statements below this line");
    // Split into two half-size zeroing calls: a single 1024-byte __bpf_memzero
    // increases verifier complexity and may be rejected on older kernels.
    __bpf_memzero(buf, TRACE_BUF_SIZE / 2);
    __bpf_memzero(buf + (TRACE_BUF_SIZE / 2), TRACE_BUF_SIZE / 2);

    long read_ret;
    if (read_user) {
        read_ret = bpf_probe_read_user(buf, buf_len, (void *)(read_base + offset));
    } else {
        // u_buf points to the kernel scratch buffer filled by read_iovec_ctx / backup paths.
        read_ret = bpf_probe_read_kernel(buf, buf_len, (void *)(read_base + offset));
    }

    if (read_ret < 0) {
        goto done_with_trace;
    }
    bpf_dbg_printk("tp chunk scanning offset=%u to_read=%u niter=%u bytes_len=%u",
                   offset,
                   buf_len,
                   args->niter,
                   effective_len);

    bool eoh_in_chunk = false;
    unsigned char *res = bpf_strstr_tp_eoh(buf, buf_len, &eoh_in_chunk);
    if (res) {
        bpf_dbg_printk("Found chunked traceparent [%s] chunk %u", res, args->niter);
        unsigned char *t_id = extract_trace_id(res);
        unsigned char *f_id = extract_flags(res);
        unsigned char *s_id = extract_span_id(res);

        decode_hex(tp_p->tp.trace_id, t_id, TRACE_ID_CHAR_LEN);
        decode_hex((unsigned char *)&tp_p->tp.flags, f_id, FLAGS_CHAR_LEN);
        if (meta->type != EVENT_HTTP_CLIENT) {
            decode_hex(tp_p->tp.parent_id, s_id, SPAN_ID_CHAR_LEN);
        }

        if (g_bpf_debug) {
            unsigned char tp_buf[TP_MAX_VAL_LENGTH];
            make_tp_string(tp_buf, &tp_p->tp);
            bpf_dbg_printk("new tp via chunk: %s", tp_buf);
        }

        __builtin_memcpy(&info->tp, &tp_p->tp, sizeof(tp_info_t));
        // Always update the connection map so downstream client spans issued
        // from the same handler see the extracted trace ID, not the generated one.
        // server_or_client_trace is skipped in append mode because it was already
        // called during initial request processing; re-calling it would produce
        // duplicate trace entries.
        set_trace_info_for_connection(&args->pid_conn.conn, type, tp_p);
        if (!args->is_append) {
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

    // EOH reached in this chunk: traceparent is not in the headers section.
    if (eoh_in_chunk) {
        goto done_with_trace;
    }

    u32 next_offset = (args->niter + 1) * chunk_size;
    if (next_offset < effective_len && (base_offset + next_offset) < max_bytes &&
        args->niter + 1 < k_tp_parse_max_niter) {
        args->niter++;
        bpf_tail_call(ctx, &jump_table, k_tail_parse_traceparent_http);
    }
    // Fall through: no more chunks to scan or tail-call failed

// tp_p is non-NULL here: the only path to this label is the fall-through
// from the chunk-scan loop; the `if (!tp_p) { goto done; }` guard above
// jumps past this label when tp_p is NULL.
done_with_trace:
    if (!args->is_append) {
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
done:
    // Inline the continuation instead of tail-calling, so it executes even when
    // the tail-call budget is exhausted after the maximum number of iterations.
    // In append mode, the caller already updated info->len before the tail-call.
    if (!args->is_append) {
        return __obi_continue2_protocol_http(ctx, args, info, meta);
    }

    // Append mode: emit large buffer now that the trace ID is finalized.
    http_send_large_buffer(ctx,
                           info,
                           &args->pid_conn,
                           (void *)args->u_buf,
                           args->bytes_len,
                           args->packet_type,
                           args->direction,
                           k_large_buf_action_append);
    return 0;
}

static __always_inline int
__obi_continue_protocol_http_tp(struct pt_regs *ctx,
                                call_protocol_args_t *args,
                                http_info_t *info,
                                http_connection_metadata_t *meta,
                                unsigned char *(*tp_loop_fn)(unsigned char *, const u16)) {
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
                tp_p->tp.flags = 1;
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

        unsigned char *buf = (unsigned char *)tp_char_buf_mem();
        if (buf) {
            // Clamp (not mask) to TRACE_BUF_SIZE-1: the old `& (TRACE_BUF_SIZE-1)`
            // silently zeroed buf_len when bytes_len == TRACE_BUF_SIZE.
            // Keep one byte for the NUL terminator used by debug printing while still
            // scanning almost the full first chunk. The chunked parser starts at the
            // next overlapping step, so this does not leave an unscanned gap.
            u16 buf_len = args->bytes_len;
            bpf_clamp_umax(buf_len, TRACE_BUF_SIZE - 1);

            bpf_probe_read(buf, buf_len, (void *)args->u_buf);
            // null terminate to make proper string
            buf[buf_len] = '\0';

            unsigned char *res = tp_loop_fn(buf, buf_len);
            if (res) {
                bpf_dbg_printk("Found traceparent in headers [%s] overriding what was before", res);
                unsigned char *t_id = extract_trace_id(res);
                unsigned char *s_id = extract_span_id(res);
                unsigned char *f_id = extract_flags(res);
                const bool is_client = meta && meta->type == EVENT_HTTP_CLIENT;
                unsigned char *previous_trace_id = NULL;

                if (is_client && valid_trace(tp_p->tp.trace_id)) {
                    previous_trace_id = (unsigned char *)http_previous_trace_id_mem();
                    if (previous_trace_id) {
                        __builtin_memcpy(previous_trace_id, tp_p->tp.trace_id, TRACE_ID_SIZE_BYTES);
                    }
                }

                decode_hex(tp_p->tp.trace_id, t_id, TRACE_ID_CHAR_LEN);
                decode_hex((unsigned char *)&tp_p->tp.flags, f_id, FLAGS_CHAR_LEN);
                if (meta && meta->type != EVENT_HTTP_CLIENT) {
                    decode_hex(tp_p->tp.parent_id, s_id, SPAN_ID_CHAR_LEN);
                } else if (previous_trace_id &&
                           bpf_memcmp(previous_trace_id, tp_p->tp.trace_id, TRACE_ID_SIZE_BYTES) !=
                               0) {
                    __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
                }

                if (g_bpf_debug) {
                    unsigned char tp_buf[TP_MAX_VAL_LENGTH];
                    make_tp_string(tp_buf, &tp_p->tp);
                    bpf_dbg_printk("new tp: %s", tp_buf);
                }
            } else {
                bpf_dbg_printk("No additional traceparent in headers, using what was made before");
                // If total data exceeds the first scan window, launch the chunked
                // scanner starting at niter=1 (the first chunk was already scanned).
                const u32 total_len =
                    (args->orig_buf && (u32)args->full_bytes_len > (u32)args->bytes_len)
                        ? (u32)args->full_bytes_len
                        : (u32)args->bytes_len;
                if (tp_loop_fn == bpf_strstr_tp_loop && bpf_max_request_tp_parse_size_kb > 0 &&
                    total_len > (TRACE_BUF_SIZE - 1)) {
                    args->niter = 1;
                    bpf_tail_call(ctx, &jump_table, k_tail_parse_traceparent_http);
                }
            }
        } else {
            goto done;
        }
    }

    if (meta) {
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

done:
    if (tp_loop_fn == bpf_strstr_tp_loop) {
        return __obi_continue2_protocol_http(ctx, args, info, meta);
    } else {
        bpf_tail_call(ctx, &jump_table, k_tail_continue2_protocol_http);
        return 0;
    }
}

// k_tail_continue_protocol_http_tp
SEC("kprobe/http")
int obi_continue_protocol_http_tp(struct pt_regs *ctx) {
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

    return __obi_continue_protocol_http_tp(ctx, args, info, meta, bpf_strstr_tp_loop__legacy);
}

static __always_inline int
__obi_continue_protocol_http(struct pt_regs *ctx,
                             call_protocol_args_t *args,
                             http_info_t *info,
                             unsigned char *(*tp_loop_fn)(unsigned char *, const u16)) {
    http_connection_metadata_t *meta =
        connection_meta_by_direction(args->direction, PACKET_TYPE_REQUEST);

    egress_key_t e_key = {
        .d_port = args->pid_conn.conn.d_port,
        .s_port = args->pid_conn.conn.s_port,
    };

    sort_egress_key(&e_key);

    tp_info_pid_t *tp_p = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);

    if (tp_p && tp_p->req_type == EVENT_HTTP_CLIENT && tp_p->written &&
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
        if (meta->type == EVENT_HTTP_CLIENT) {
            pid_connection_info_t p_conn = {.pid = args->pid_conn.pid};
            __builtin_memcpy(&p_conn.conn, &args->pid_conn.conn, sizeof(connection_info_t));
            found_tp = find_trace_for_client_request(
                &p_conn, args->orig_dport, args->lw_thread, &tp_p->tp);
        } else {
            //bpf_dbg_printk("Looking up existing trace for connection");
            //dbg_print_http_connection_info(conn);

            // For server requests, we first look for TCP info (setup by TC ingress) and then we fall back to black-box info.
            found_tp =
                find_trace_for_server_request(&args->pid_conn.conn, &tp_p->tp, EVENT_HTTP_REQUEST);
        }
    }

    if (!found_tp) {
        bpf_dbg_printk("Generating new traceparent id");
        new_trace_id(&tp_p->tp);
        __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
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
        if (meta->type == EVENT_HTTP_REQUEST && found_tp && args->ssl) {
            bpf_dbg_printk("skipping headers parsing because of existing tp info for SSL call");
            args->skip_tp_parsing = 1;
        }
    }

    if (tp_loop_fn == bpf_strstr_tp_loop) {
        return __obi_continue_protocol_http_tp(ctx, args, info, meta, tp_loop_fn);
    } else {
        bpf_tail_call(ctx, &jump_table, k_tail_continue_protocol_http_tp);
        return 0;
    }

skip_tp:
    if (tp_loop_fn == bpf_strstr_tp_loop) {
        return __obi_continue2_protocol_http(ctx, args, info, meta);
    } else {
        bpf_tail_call(ctx, &jump_table, k_tail_continue2_protocol_http);
        return 0;
    }
}

// k_tail_continue_protocol_http (legacy)
SEC("kprobe/http")
int obi_continue_protocol_http_legacy(struct pt_regs *ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
    if (!info) {
        return 0;
    }

    return __obi_continue_protocol_http(ctx, args, info, bpf_strstr_tp_loop__legacy);
}

// k_tail_continue_protocol_http (new kernels)
SEC("kprobe/http")
int obi_continue_protocol_http(struct pt_regs *ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
    if (!info) {
        return 0;
    }

    if (args->use_bpf_loop) {
        return __obi_continue_protocol_http(ctx, args, info, bpf_strstr_tp_loop);
    }

    return __obi_continue_protocol_http(ctx, args, info, bpf_strstr_tp_loop__legacy);
}

static __always_inline int
__obi_protocol_http(struct pt_regs *ctx, unsigned char *(*tp_loop_fn)(unsigned char *, const u16)) {
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

    http_info_t *info =
        get_or_set_http_info(in, &args->pid_conn, args->packet_type, args->direction);
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

        args->use_bpf_loop = tp_loop_fn == bpf_strstr_tp_loop;
        bpf_tail_call(ctx, &jump_table, k_tail_continue_protocol_http);

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
        const u32 prev_len = info->len;
        // Update info->len before the tail-call: obi_parse_traceparent_http
        // reads info->len to derive base_offset in append mode, so it must
        // reflect the cumulative byte count including this chunk.
        info->len += args->bytes_len;
        if (g_bpf_traceparent_enabled && capture_header_buffer &&
            tp_loop_fn == bpf_strstr_tp_loop &&
            prev_len < (u32)bpf_max_request_tp_parse_size_kb * 1024) {
            args->packet_type = PACKET_TYPE_REQUEST;
            args->is_append = 1;
            args->niter = 0;
            bpf_tail_call(ctx, &jump_table, k_tail_parse_traceparent_http);
            // tail-call failed — fall through to http_send_large_buffer.
            // info->len is already updated above, which is correct: the next
            // invocation of this function for the following chunk will compute
            // base_offset from info->len and see the right cumulative offset.
        }
        // TP parsing not needed or tail-call failed: emit large buffer.
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
int obi_protocol_http(struct pt_regs *ctx) {
    return __obi_protocol_http(ctx, bpf_strstr_tp_loop);
}

// k_tail_protocol_http
SEC("kprobe/http")
int obi_protocol_http_legacy(struct pt_regs *ctx) {
    return __obi_protocol_http(ctx, bpf_strstr_tp_loop__legacy);
}

// k_tail_large_buf_emit_continue
SEC("kprobe/http")
int obi_large_buf_emit_continue(struct pt_regs *ctx) {
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

    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->packet_type = state->packet_type;
    large_buf->direction = state->direction;
    large_buf->conn_info = info->conn_info;
    large_buf->action = state->batch_iter == 0 ? state->action : k_large_buf_action_append;
    large_buf->kind = k_large_buf_layer_app;
    large_buf->tp = info->tp;
    // Use the stable original trace ID for large buffers so userspace can correlate
    // chunks even if the request's trace ID is later updated by a chunked traceparent.
    __builtin_memcpy(
        large_buf->tp.trace_id, info->original_trace_id, sizeof(large_buf->tp.trace_id));

    const u32 consumed_bytes =
        large_buf_emit_chunks(large_buf, (const void *)state->u_buf, state->remaining_bytes);

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
        bpf_tail_call_static(ctx, &jump_table, k_tail_large_buf_emit_continue);
    }

    return 0;
}
