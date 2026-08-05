// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>
#include <common/go_grpc_client_conn.h>
#include <common/hpack.h>
#include <common/iov_iter.h>
#include <common/http_buf_size.h>
#include <common/protocol_http2_helpers.h>
#include <common/ringbuf.h>
#include <common/trace_lifecycle.h>
#include <common/trace_parent.h>

#include <maps/tp_info_mem.h>
#include <maps/tp_char_buf_mem.h>

#include <generictracer/http2_client_lifecycle.h>
#include <generictracer/http2_grpc.h>
#include <generictracer/http2_server_hpack_state.h>
#include <generictracer/k_tracer_tailcall.h>
#include <generictracer/protocol_common.h>
#include <generictracer/types/http2_conn_info_data.h>

#include <generictracer/maps/grpc_frames_ctx_mem.h>
#include <generictracer/maps/http2_client_lifecycle.h>
#include <generictracer/maps/http2_client_lifecycle_mem.h>
#include <generictracer/maps/http2_conn_info_mem.h>
#include <generictracer/maps/http2_info_mem.h>
#include <generictracer/maps/client_trace_publication_mem.h>

#include <generictracer/maps/ongoing_http2_grpc.h>

#include <maps/active_ssl_connections.h>
#include <maps/ongoing_http2_connections.h>

// These are bit flags, if you add any use power of 2 values
enum { http2_conn_flag_ssl = WITH_SSL, http2_conn_flag_new = 0x2 };

static __always_inline grpc_frames_ctx_t *grpc_ctx() {
    return bpf_map_lookup_elem(&grpc_frames_ctx_mem, &(int){0});
}

static __always_inline u8 http2_flag_ssl(u8 flags) {
    return flags & http2_conn_flag_ssl;
}

static __always_inline u8 http2_flag_new(u8 flags) {
    return flags & http2_conn_flag_new;
}

enum http2_server_header_consume_result : u8 {
    k_http2_server_header_pending,
    k_http2_server_header_complete,
    k_http2_server_header_failed,
};

static __always_inline u8 begin_http2_server_hpack_transaction(grpc_frames_ctx_t *g_ctx,
                                                               http2_conn_info_data_t *connection) {
    if (!g_ctx || !connection) {
        return 0;
    }

    const http2_server_hpack_lease_key_t key =
        http2_server_hpack_lease_key(&g_ctx->stream.pid_conn, connection);
    const u64 token = new_http2_server_hpack_lease_token();
    if (!claim_http2_server_hpack_lease(&key, token)) {
        // Raw retirement is a generation-local monotonic tombstone, so this
        // callback cannot lose a last-check race with the current owner.
        retire_http2_server_hpack_generation(&key);
        return 0;
    }

    g_ctx->server_hpack_lease_key = key;
    g_ctx->server_hpack_lease_token = token;
    g_ctx->server_hpack_lease_active = 1;
    return 1;
}

static __always_inline http2_server_hpack_state_t *
owned_http2_server_hpack_state(grpc_frames_ctx_t *g_ctx, http2_server_hpack_lease_t **lease_out) {
    if (lease_out) {
        *lease_out = NULL;
    }
    if (!g_ctx || !g_ctx->server_hpack_lease_active) {
        return NULL;
    }
    http2_conn_info_data_t *connection = current_http2_connection(&g_ctx->stream.pid_conn);
    if (!http2_server_hpack_generation_matches(
            &g_ctx->server_hpack_lease_key, &g_ctx->stream.pid_conn, connection)) {
        return NULL;
    }
    http2_server_hpack_lease_t *lease =
        bpf_map_lookup_elem(&http2_server_hpack_leases, &g_ctx->server_hpack_lease_key);
    if (!lease || lease->token != g_ctx->server_hpack_lease_token) {
        return NULL;
    }
    if (lease_out) {
        *lease_out = lease;
    }
    return lookup_http2_server_hpack_state(&g_ctx->server_hpack_lease_key);
}

static __always_inline void release_http2_server_hpack_transaction(grpc_frames_ctx_t *g_ctx) {
    if (!g_ctx || !g_ctx->server_hpack_lease_active) {
        return;
    }
    http2_server_hpack_lease_t *lease =
        bpf_map_lookup_elem(&http2_server_hpack_leases, &g_ctx->server_hpack_lease_key);
    const u8 owns = lease && lease->token == g_ctx->server_hpack_lease_token;
    const u8 poisoned = owns && lease->poisoned;
    http2_conn_info_data_t *connection =
        bpf_map_lookup_elem(&ongoing_http2_connections, &g_ctx->server_hpack_lease_key.pid_conn);
    const u8 exact = http2_server_hpack_generation_matches(
        &g_ctx->server_hpack_lease_key, &g_ctx->server_hpack_lease_key.pid_conn, connection);
    if (poisoned && exact && connection) {
        connection->retired = 1;
    }
    u8 retired = 0;
    if (exact && connection) {
        retired = connection->retired;
    }
    if (poisoned || retired || !exact) {
        bpf_map_delete_elem(&http2_server_hpack_states, &g_ctx->server_hpack_lease_key);
    }
    if (owns && retired) {
        // The non-LRU raw map and exact lease prevent an eviction/reinsert ABA
        // between this generation check and tuple delete.
        bpf_map_delete_elem(&ongoing_http2_connections, &g_ctx->server_hpack_lease_key.pid_conn);
    }
    release_http2_server_hpack_lease(&g_ctx->server_hpack_lease_key,
                                     g_ctx->server_hpack_lease_token);
    g_ctx->server_hpack_lease_active = 0;
}

static __always_inline void abort_http2_server_hpack_transaction(grpc_frames_ctx_t *g_ctx,
                                                                 u8 desync) {
    http2_server_hpack_lease_t *lease = NULL;
    http2_server_hpack_state_t *state = owned_http2_server_hpack_state(g_ctx, &lease);
    if (state) {
        if (desync || (lease && lease->poisoned)) {
            state->desynced = 1;
            hpack_dynamic_name_state_invalidate(&state->dynamic);
        }
        h2_hpack_stream_reset(&state->headers);
    }
    release_http2_server_hpack_transaction(g_ctx);
}

static __always_inline u8 preserve_http2_server_header_fragment(grpc_frames_ctx_t *g_ctx) {
    http2_server_hpack_lease_t *lease = NULL;
    http2_server_hpack_state_t *state = owned_http2_server_hpack_state(g_ctx, &lease);
    if (!state || !lease || lease->poisoned) {
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }
    release_http2_server_hpack_transaction(g_ctx);
    return 1;
}

static __noinline u8 consume_http2_server_header_bytes(grpc_frames_ctx_t *g_ctx,
                                                       http2_server_hpack_state_t *state,
                                                       u32 buffer_pos) {
    if (!g_ctx || !state || g_ctx->args.bytes_len <= 0 ||
        buffer_pos >= (u32)g_ctx->args.bytes_len) {
        return k_http2_server_header_failed;
    }
    unsigned char *scratch = tp_char_buf_mem();
    if (!scratch) {
        return k_http2_server_header_failed;
    }

    u32 available = (u32)g_ctx->args.bytes_len - buffer_pos;
    u32 read_len = available;
    if (read_len > k_kprobes_http2_buf_size) {
        read_len = k_kprobes_http2_buf_size;
    }
    bpf_clamp_umax(read_len, k_kprobes_http2_buf_size);
    const void *source = (const void *)(g_ctx->args.u_buf + buffer_pos);
    if (!read_len || bpf_probe_read(scratch, read_len, source) != 0) {
        return k_http2_server_header_failed;
    }

    u16 consumed = 0;
    h2_hpack_stream_consume(&state->headers, scratch, read_len, &consumed);
    if (state->headers.complete) {
        if (g_ctx->server_hpack_blocks < 0xff) {
            g_ctx->server_hpack_blocks++;
        }
        const u32 next_pos = buffer_pos + consumed;
        if (next_pos <= (u32)g_ctx->args.bytes_len) {
            g_ctx->pos = next_pos;
            g_ctx->server_hpack_resume_pending =
                h2_hpack_stream_has_trailing_bytes(available, consumed);
            if (g_ctx->server_hpack_resume_pending) {
                g_ctx->server_hpack_resume_key = g_ctx->server_hpack_lease_key;
            }
        } else {
            h2_hpack_stream_fail_framing(&state->headers);
        }
    }
    if (available > read_len && !state->headers.complete) {
        // The bounded capture cannot locate a continuation header beyond this
        // chunk. Never commit a table that may have skipped HPACK insertions.
        h2_hpack_stream_fail_framing(&state->headers);
    }
    if (state->headers.framing_invalid) {
        return k_http2_server_header_failed;
    }
    if (state->headers.complete) {
        g_ctx->stream.stream_id = state->headers.stream_id;
        return k_http2_server_header_complete;
    }
    return k_http2_server_header_pending;
}

static __always_inline http2_grpc_request_t *empty_http2_info() {
    http2_grpc_request_t *value = http2_info_mem();
    if (value) {
        bpf_memset(value, 0, sizeof(http2_grpc_request_t));
    }
    return value;
}

static __always_inline http2_conn_info_data_t *empty_http2_conn_info() {
    http2_conn_info_data_t *value = http2_conn_info_mem();
    if (value) {
        value->id = 0;
        value->process_start_time = 0;
        value->connection_time = 0;
        value->flags = 0;
        __builtin_memset(value->_pad, 0, sizeof(value->_pad));
    }
    return value;
}

static __always_inline u64 uniqueHTTP2ConnId(pid_connection_info_t *p_conn) {
    (void)p_conn;
    u64 random_id = ((u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();
    if (!random_id) {
        random_id = bpf_ktime_get_ns();
    }
    return random_id ? random_id : 1;
}

enum injected_trace_adoption : u8 {
    k_injected_trace_none,
    k_injected_trace_handoff,
    k_injected_trace_fail_closed,
};

// Use the full stream-keyed trace that a producer reserved before touching
// wire bytes. The caller commits local consumption only after it has durable
// per-request state.
static __always_inline u8 adopt_injected_trace(http2_conn_stream_t *s_key,
                                               tp_info_t *tp,
                                               outgoing_trace_token_t *claimed_token,
                                               tp_info_pid_t *claimed_trace,
                                               egress_key_t *egress) {
    make_egress_key_into(egress, &s_key->pid_conn.conn, s_key->pid_conn.pid, s_key->stream_id);
    const u8 resolution = resolve_and_claim_current_outgoing_trace_handoff(
        egress, s_key->pid_conn.pid, EVENT_HTTP_CLIENT, NULL, 1, 1, claimed_token, claimed_trace);
    if (resolution == k_outgoing_trace_exact) {
        if (claimed_trace->written == k_outbound_trace_written &&
            adopt_outgoing_trace_handoff(tp, claimed_trace)) {
            return k_injected_trace_handoff;
        }
        // Pending authority has not been proven on wire (notably Go TLS,
        // where sk_msg sees ciphertext). Its presence suppresses generic B but
        // cannot authorize adoption of A.
        return k_injected_trace_fail_closed;
    }
    if (resolution == k_outgoing_trace_fail_closed ||
        (resolution == k_outgoing_trace_absent && is_go_h2_client_conn(&s_key->pid_conn))) {
        return k_injected_trace_fail_closed;
    }
    return k_injected_trace_none;
}

static __always_inline tp_info_pid_t
h2_client_event_publication(const http2_conn_stream_t *s_key, const http2_grpc_request_t *request) {
    return (tp_info_pid_t){
        .tp = request->tp,
        .pid = s_key->pid_conn.pid,
        .valid = 1,
        .written = k_outbound_trace_pending,
        .req_type = EVENT_HTTP_CLIENT,
    };
}

static __noinline void apply_h2_client_sampling_decision(tp_info_t *tp, u8 found_parent) {
    apply_sampling_decision(tp, found_parent, 0);
}

static __noinline void cleanup_h2_client_publication(const http2_conn_stream_t *s_key,
                                                     const http2_grpc_request_t *request,
                                                     const tp_info_pid_t *publication) {
    delete_client_trace_publications_if_matches(&request->conn_info,
                                                publication,
                                                s_key->pid_conn.pid,
                                                s_key->stream_id,
                                                request->ssl,
                                                request->owner_pid_tgid,
                                                request->owner_vt_keyed);
}

static __noinline u8 publish_h2_client_request(const http2_conn_stream_t *s_key,
                                               const http2_grpc_request_t *request,
                                               const tp_info_pid_t *publication,
                                               u8 outgoing_noexist) {
    http2_client_lifecycle_scratch_t *scratch = http2_client_lifecycle_mem();
    if (!scratch) {
        return 0;
    }
    scratch->lifecycle_key = http2_client_lifecycle_key(s_key, request->start_monotime_ns);
    if (bpf_map_lookup_elem(&h2c_completed, &scratch->lifecycle_key)) {
        return 1;
    }

    const client_trace_publication_target_t target = {
        .owner_pid_tgid = request->owner_pid_tgid,
        .host_pid = s_key->pid_conn.pid,
        .stream_id = s_key->stream_id,
        .ssl = request->ssl,
        .vt_keyed = request->owner_vt_keyed,
        .outgoing_noexist = outgoing_noexist,
    };
    client_trace_publication_transaction_t *transaction =
        client_trace_publication_transaction_mem();
    if (!transaction) {
        return 0;
    }
    if (begin_client_trace_publications(&request->conn_info, publication, &target, transaction) !=
        0) {
        rollback_client_trace_publications(&request->conn_info, publication, &target, transaction);
        finish_client_trace_publications(&request->conn_info, &target, transaction);
        return 0;
    }
    finish_client_trace_publications(&request->conn_info, &target, transaction);

    return bpf_map_lookup_elem(&h2c_completed, &scratch->lifecycle_key) != NULL;
}

// The exact upgrade becomes immutable per-request state before the producer's
// action claim is consumed. Shared publication can then fail or contend
// without erasing the client event that the terminal path will use.
static __noinline u8 commit_h2_client_handoff(http2_conn_stream_t *s_key,
                                              http2_grpc_request_t *request,
                                              const tp_info_pid_t *publication,
                                              const outgoing_trace_token_t *token) {
    http2_client_lifecycle_scratch_t *scratch = http2_client_lifecycle_mem();
    if (!scratch) {
        return 0;
    }
    make_egress_key_into(
        &scratch->egress, &s_key->pid_conn.conn, s_key->pid_conn.pid, s_key->stream_id);
    scratch->lifecycle_key = http2_client_lifecycle_key(s_key, request->start_monotime_ns);
    if (bpf_map_lookup_elem(&h2c_completed, &scratch->lifecycle_key)) {
        release_claimed_outgoing_trace_handoff(&scratch->egress, token);
        return 0;
    }

    scratch->upgrade.publication = *publication;
    scratch->upgrade.token = *token;
    if (bpf_map_update_elem(
            &h2c_upgrades, &scratch->lifecycle_key, &scratch->upgrade, BPF_NOEXIST) != 0) {
        release_claimed_outgoing_trace_handoff(&scratch->egress, token);
        return 0;
    }

    request->tp = publication->tp;
    request->handoff_token = *token;
    request->handoff_expected = 1;
    consume_claimed_outgoing_trace_handoff(&scratch->egress, token);

    if (bpf_map_lookup_elem(&h2c_completed, &scratch->lifecycle_key)) {
        cleanup_outgoing_trace_handoff_token(
            &scratch->egress, s_key->pid_conn.pid, EVENT_HTTP_CLIENT, token);
        bpf_map_delete_elem(&h2c_upgrades, &scratch->lifecycle_key);
    }
    return 1;
}

// SERVER finalize: shared post-branch tail of http2_grpc_start. h2g_info /
// tp_p are populated in per-CPU scratch by the caller
static __always_inline void http2_grpc_start_finalize_server(http2_conn_stream_t *s_key,
                                                             http2_grpc_request_t *h2g_info,
                                                             tp_info_pid_t *tp_p,
                                                             u8 found_tp,
                                                             u8 ssl,
                                                             u16 orig_dport) {
    if (!found_tp) {
        new_trace_id(&tp_p->tp);
        bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    }
    apply_sampling_decision(&tp_p->tp, found_tp, found_tp);

    h2g_info->tp = tp_p->tp;

    set_trace_info_for_connection(&h2g_info->conn_info, TRACE_TYPE_SERVER, tp_p);
    server_or_client_trace(EVENT_HTTP_REQUEST,
                           &h2g_info->conn_info,
                           k_lw_thread_none,
                           tp_p,
                           ssl,
                           orig_dport,
                           0,
                           BPF_ANY);

    trace_key_t t_key = {0};
    task_tid(&t_key.p_key);
    java_vt_translate_tid(&t_key.p_key);
    t_key.extra_id = extra_runtime_id();
    bpf_map_update_elem(&server_traces, &t_key, tp_p, BPF_ANY);

    bpf_map_update_elem(&ongoing_http2_grpc, s_key, h2g_info, BPF_ANY);
}

static __noinline u8 finish_h2_client_if_terminal(http2_conn_stream_t *stream,
                                                  const http2_client_lifecycle_key_t *lifecycle_key,
                                                  http2_grpc_request_t *request) {
    http2_client_lifecycle_scratch_t *scratch = http2_client_lifecycle_mem();
    if (!scratch) {
        return 0;
    }
    scratch->lifecycle_key = *lifecycle_key;
    http2_client_terminal_t *terminal =
        bpf_map_lookup_elem(&h2c_terminals, &scratch->lifecycle_key);
    http2_grpc_request_t *base = bpf_map_lookup_elem(&ongoing_http2_grpc, stream);
    if (!terminal || !base || !scratch || base->type != EVENT_HTTP_CLIENT ||
        base->start_monotime_ns != scratch->lifecycle_key.start_monotime_ns) {
        return 0;
    }
    scratch->terminal = *terminal;
    *request = *base;

    http2_client_trace_upgrade_t *upgrade =
        bpf_map_lookup_elem(&h2c_upgrades, &scratch->lifecycle_key);
    u8 has_exact_upgrade = upgrade != NULL;
    if (upgrade) {
        scratch->upgrade = *upgrade;
    }

    __builtin_memset(&scratch->located_token, 0, sizeof(scratch->located_token));
    make_egress_key_into(
        &scratch->egress, &stream->pid_conn.conn, stream->pid_conn.pid, stream->stream_id);
    const u8 exact_locator_present =
        !request->handoff_expected &&
        current_outgoing_trace_handoff_token(&scratch->egress, &scratch->located_token);

    if (!request->handoff_expected && !has_exact_upgrade && exact_locator_present) {
        __builtin_memset(&scratch->upgrade, 0, sizeof(scratch->upgrade));
        const u8 adoption = adopt_injected_trace(stream,
                                                 &request->tp,
                                                 &scratch->upgrade.token,
                                                 &scratch->upgrade.publication,
                                                 &scratch->egress);
        if (adoption == k_injected_trace_handoff) {
            has_exact_upgrade = commit_h2_client_handoff(
                stream, request, &scratch->upgrade.publication, &scratch->upgrade.token);
            if (has_exact_upgrade &&
                publish_h2_client_request(stream, request, &scratch->upgrade.publication, 0)) {
                cleanup_h2_client_publication(stream, request, &scratch->upgrade.publication);
            }
        } else if (outgoing_trace_token_valid(&scratch->upgrade.token)) {
            release_claimed_outgoing_trace_handoff(&scratch->egress, &scratch->upgrade.token);
            request_outgoing_trace_handoff_retirement(
                &scratch->egress, &scratch->upgrade.token, NULL, 0);
        } else {
            request_outgoing_trace_handoff_retirement(
                &scratch->egress, &scratch->located_token, NULL, 0);
        }
    }

    const enum http2_client_completion_resolution resolution =
        request->handoff_expected
            ? k_http2_client_completion_exact
            : http2_client_completion_resolution(has_exact_upgrade, exact_locator_present);

    const u8 completed = 1;
    if (bpf_map_update_elem(&h2c_completed, &scratch->lifecycle_key, &completed, BPF_NOEXIST) !=
        0) {
        return 0;
    }

    base = bpf_map_lookup_elem(&ongoing_http2_grpc, stream);
    if (!base || base->type != EVENT_HTTP_CLIENT ||
        base->start_monotime_ns != scratch->lifecycle_key.start_monotime_ns) {
        bpf_map_delete_elem(&h2c_terminals, &scratch->lifecycle_key);
        bpf_map_delete_elem(&h2c_upgrades, &scratch->lifecycle_key);
        return 0;
    }

    scratch->cleanup_publication = h2_client_event_publication(stream, base);
    cleanup_h2_client_publication(stream, base, &scratch->cleanup_publication);
    *request = *base;

    upgrade = bpf_map_lookup_elem(&h2c_upgrades, &scratch->lifecycle_key);
    if (upgrade) {
        scratch->upgrade = *upgrade;
        request->tp = scratch->upgrade.publication.tp;
        request->handoff_token = scratch->upgrade.token;
        request->handoff_expected = 1;
    }
    request->end_monotime_ns = scratch->terminal.end_monotime_ns;
    __builtin_memcpy(request->ret_data, scratch->terminal.ret_data, sizeof(request->ret_data));

    const u8 suppress_event =
        !request->handoff_expected && (resolution == k_http2_client_completion_fail_closed ||
                                       is_go_h2_client_conn(&stream->pid_conn));
    if (!suppress_event) {
        http2_grpc_request_t *trace = bpf_ringbuf_reserve(&events, sizeof(http2_grpc_request_t), 0);
        if (trace) {
            __builtin_memcpy(trace, request, sizeof(*trace));
            bpf_ringbuf_submit(trace, get_flags());
        }
    }

    base = bpf_map_lookup_elem(&ongoing_http2_grpc, stream);
    if (base && base->start_monotime_ns == scratch->lifecycle_key.start_monotime_ns) {
        bpf_map_delete_elem(&ongoing_http2_grpc, stream);
    }

    scratch->cleanup_publication = h2_client_event_publication(stream, request);
    cleanup_h2_client_publication(stream, request, &scratch->cleanup_publication);
    if (request->handoff_expected) {
        cleanup_outgoing_trace_handoff_token(
            &scratch->egress, stream->pid_conn.pid, EVENT_HTTP_CLIENT, &request->handoff_token);
    }
    bpf_map_delete_elem(&h2c_terminals, &scratch->lifecycle_key);
    bpf_map_delete_elem(&h2c_upgrades, &scratch->lifecycle_key);
    return 1;
}

static __always_inline void http2_grpc_start(void *ctx,
                                             http2_conn_stream_t *s_key,
                                             void *u_buf,
                                             int len,
                                             u8 direction,
                                             u8 ssl,
                                             u16 orig_dport) {
    const u8 server_direction =
        request_type_by_direction(direction, PACKET_TYPE_REQUEST) == EVENT_HTTP_REQUEST;
    http_connection_metadata_t *meta = connection_meta_by_direction(direction, PACKET_TYPE_REQUEST);
    if (!meta) {
        bpf_dbg_printk("Can't get meta memory or connection not found");
        if (server_direction) {
            abort_http2_server_hpack_transaction(grpc_ctx(), 1);
        }
        return;
    }
    const u8 is_client = http2_uses_client_publication_lane(meta->type);

    http2_grpc_request_t *existing = bpf_map_lookup_elem(&ongoing_http2_grpc, s_key);
    if (existing) {
        bpf_dbg_printk("already found existing grpcstart, ignoring this exchange");
        if (!is_client || existing->type != EVENT_HTTP_CLIENT) {
            if (!is_client) {
                abort_http2_server_hpack_transaction(grpc_ctx(), 1);
            }
            return;
        }

        http2_grpc_request_t *updated = empty_http2_info();
        if (!updated) {
            return;
        }
        *updated = *existing;
        http2_client_lifecycle_scratch_t *scratch = http2_client_lifecycle_mem();
        if (!scratch) {
            return;
        }
        scratch->lifecycle_key = http2_client_lifecycle_key(s_key, updated->start_monotime_ns);
        if (bpf_map_lookup_elem(&h2c_completed, &scratch->lifecycle_key)) {
            return;
        }

        if (!updated->handoff_expected &&
            !bpf_map_lookup_elem(&h2c_upgrades, &scratch->lifecycle_key)) {
            __builtin_memset(&scratch->upgrade, 0, sizeof(scratch->upgrade));
            const u8 adoption = adopt_injected_trace(s_key,
                                                     &updated->tp,
                                                     &scratch->upgrade.token,
                                                     &scratch->upgrade.publication,
                                                     &scratch->egress);
            if (adoption == k_injected_trace_handoff) {
                if (commit_h2_client_handoff(
                        s_key, updated, &scratch->upgrade.publication, &scratch->upgrade.token) &&
                    publish_h2_client_request(s_key, updated, &scratch->upgrade.publication, 0)) {
                    cleanup_h2_client_publication(s_key, updated, &scratch->upgrade.publication);
                }
            } else if (outgoing_trace_token_valid(&scratch->upgrade.token)) {
                make_egress_key_into(
                    &scratch->egress, &s_key->pid_conn.conn, s_key->pid_conn.pid, s_key->stream_id);
                release_claimed_outgoing_trace_handoff(&scratch->egress, &scratch->upgrade.token);
            }
        }
        bpf_tail_call_static(ctx, &jump_table, k_tail_protocol_http2_grpc_finish_client);
        return;
    }

    http2_grpc_request_t *h2g_info = empty_http2_info();
    bpf_dbg_printk("http2/grpc start direction=%d stream=%d", direction, s_key->stream_id);
    //dbg_print_http_connection_info(&s_key->pid_conn.conn); // commented out since GitHub CI doesn't like this call
    if (!h2g_info) {
        if (!is_client) {
            abort_http2_server_hpack_transaction(grpc_ctx(), 1);
        }
        return;
    }

    h2g_info->flags = EVENT_K_HTTP2_REQUEST;
    h2g_info->start_monotime_ns = bpf_ktime_get_ns();
    h2g_info->owner_pid_tgid = bpf_get_current_pid_tgid();
    h2g_info->owner_vt_keyed = java_vt_mounted();
    h2g_info->len = len;
    h2g_info->ssl = ssl;
    h2g_info->conn_info = s_key->pid_conn.conn;
    h2g_info->pid = meta->pid;
    h2g_info->type = meta->type;

    h2g_info->new_conn_id = 0;
    http2_conn_info_data_t *h2g = current_http2_connection(&s_key->pid_conn);
    if (h2g && http2_flag_new(h2g->flags)) {
        h2g_info->new_conn_id = h2g->id;
    }

    fixup_connection_info(&h2g_info->conn_info, is_client, orig_dport);
    if (!is_client) {
        grpc_frames_ctx_t *g_ctx = grpc_ctx();
        http2_server_hpack_lease_t *lease = NULL;
        http2_server_hpack_state_t *state = owned_http2_server_hpack_state(g_ctx, &lease);
        if (!state || !lease || !state->headers.complete ||
            state->headers.stream_id != s_key->stream_id) {
            abort_http2_server_hpack_transaction(g_ctx, 1);
            return;
        }
        if (lease->poisoned || state->desynced || state->headers.invalid) {
            state->desynced = 1;
            hpack_dynamic_name_state_invalidate(&state->dynamic);
            g_ctx->server_hpack_fail_closed = 1;
        }
        __builtin_memcpy(h2g_info->data, state->headers.raw, k_kprobes_http2_buf_size);
        h2g_info->len = state->headers.raw_len;
    } else {
        bpf_probe_read(h2g_info->data, k_kprobes_http2_buf_size, u_buf);
    }

    tp_info_pid_t *tp_p = tp_info_mem();
    http2_client_lifecycle_scratch_t *scratch = http2_client_lifecycle_mem();
    if (!tp_p || !scratch) {
        bpf_map_update_elem(
            &ongoing_http2_grpc, s_key, h2g_info, is_client ? BPF_NOEXIST : BPF_ANY);
        if (!is_client) {
            abort_http2_server_hpack_transaction(grpc_ctx(), 1);
        }
        return;
    }

    // Clear trace/parent IDs — per-CPU scratch carries stale data and the
    // server finalize uses valid_trace(trace_id) to decide whether to keep
    // a parsed/looked-up traceparent or generate a fresh one
    bpf_memset(tp_p->tp.trace_id, 0, sizeof(tp_p->tp.trace_id));
    bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->tp.flags = k_flag_sampled;
    reset_sampling_decision(&tp_p->tp);
    tp_p->valid = 1;
    tp_p->written = 0;
    tp_p->pid = s_key->pid_conn.pid;
    tp_p->req_type = meta->type;
    urand_bytes(tp_p->tp.span_id, SPAN_ID_SIZE_BYTES);

    if (!is_client) {
        // Server finalize tail-called to stay under verifier insn limit on 5.15
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server);
        discard_trace_for_server_request(&s_key->pid_conn.conn);
        abort_http2_server_hpack_transaction(grpc_ctx(), 1);
        return;
    }

    cp_support_data_t *cp = bpf_map_lookup_elem(&cp_support_connect_info, &s_key->pid_conn);
    if (cp) {
        // Refresh per stream — persistent H2 clients (Node grpc-js) carry a
        // stale extra_id from the first connect
        task_tid(&cp->t_key.p_key);
        java_vt_translate_tid(&cp->t_key.p_key);
        cp->t_key.extra_id = extra_runtime_id();
        cp->ts = bpf_ktime_get_ns();
    }
    u8 found_tp =
        find_trace_for_client_request(&s_key->pid_conn, orig_dport, k_lw_thread_none, &tp_p->tp);
    __builtin_memset(&scratch->upgrade, 0, sizeof(scratch->upgrade));
    const u8 adopted_trace = adopt_injected_trace(
        s_key, &tp_p->tp, &scratch->upgrade.token, &scratch->upgrade.publication, &scratch->egress);
    if (valid_trace(tp_p->tp.trace_id)) {
        found_tp = 1;
    }

    if (!found_tp) {
        new_trace_id(&tp_p->tp);
        bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    }
    if (adopted_trace != k_injected_trace_handoff) {
        apply_h2_client_sampling_decision(&tp_p->tp, found_tp);
    }

    h2g_info->tp = tp_p->tp;
    if (adopted_trace == k_injected_trace_handoff) {
        h2g_info->handoff_token = scratch->upgrade.token;
        h2g_info->handoff_expected = 1;
    }

    if (bpf_map_update_elem(&ongoing_http2_grpc, s_key, h2g_info, BPF_NOEXIST) != 0) {
        if (adopted_trace == k_injected_trace_handoff) {
            existing = bpf_map_lookup_elem(&ongoing_http2_grpc, s_key);
            if (existing && existing->type == EVENT_HTTP_CLIENT) {
                *h2g_info = *existing;
                if (commit_h2_client_handoff(
                        s_key, h2g_info, &scratch->upgrade.publication, &scratch->upgrade.token) &&
                    publish_h2_client_request(s_key, h2g_info, &scratch->upgrade.publication, 0)) {
                    cleanup_h2_client_publication(s_key, h2g_info, &scratch->upgrade.publication);
                }
                bpf_tail_call_static(ctx, &jump_table, k_tail_protocol_http2_grpc_finish_client);
                return;
            }
        }
        if (outgoing_trace_token_valid(&scratch->upgrade.token)) {
            make_egress_key_into(
                &scratch->egress, &s_key->pid_conn.conn, s_key->pid_conn.pid, s_key->stream_id);
            release_claimed_outgoing_trace_handoff(&scratch->egress, &scratch->upgrade.token);
        }
        return;
    }

    scratch->lifecycle_key = http2_client_lifecycle_key(s_key, h2g_info->start_monotime_ns);
    if (adopted_trace == k_injected_trace_handoff) {
        make_egress_key_into(
            &scratch->egress, &s_key->pid_conn.conn, s_key->pid_conn.pid, s_key->stream_id);
        consume_claimed_outgoing_trace_handoff(&scratch->egress, &scratch->upgrade.token);
        if (publish_h2_client_request(s_key, h2g_info, &scratch->upgrade.publication, 0)) {
            cleanup_h2_client_publication(s_key, h2g_info, &scratch->upgrade.publication);
        }
        if (bpf_map_lookup_elem(&h2c_completed, &scratch->lifecycle_key)) {
            cleanup_outgoing_trace_handoff_token(
                &scratch->egress, s_key->pid_conn.pid, EVENT_HTTP_CLIENT, &scratch->upgrade.token);
        }
    } else if (adopted_trace == k_injected_trace_none) {
        scratch->cleanup_publication = h2_client_event_publication(s_key, h2g_info);
        if (publish_h2_client_request(s_key, h2g_info, &scratch->cleanup_publication, 1)) {
            cleanup_h2_client_publication(s_key, h2g_info, &scratch->cleanup_publication);
        }
    } else if (outgoing_trace_token_valid(&scratch->upgrade.token)) {
        make_egress_key_into(
            &scratch->egress, &s_key->pid_conn.conn, s_key->pid_conn.pid, s_key->stream_id);
        release_claimed_outgoing_trace_handoff(&scratch->egress, &scratch->upgrade.token);
    }
    bpf_tail_call_static(ctx, &jump_table, k_tail_protocol_http2_grpc_finish_client);
}

static __always_inline void http2_grpc_end(void *ctx,
                                           http2_conn_stream_t *stream,
                                           http2_grpc_request_t *prev_info,
                                           void *u_buf) {
    bpf_dbg_printk("http2/grpc end prev_info=%llx", prev_info);
    if (!prev_info) {
        bpf_map_delete_elem(&ongoing_http2_grpc, stream);
        return;
    }

    const u8 is_client = prev_info->type == EVENT_HTTP_CLIENT;
    if (is_client) {
        const http2_grpc_request_t *current = bpf_map_lookup_elem(&ongoing_http2_grpc, stream);
        if (!current || current->type != EVENT_HTTP_CLIENT) {
            return;
        }
        *prev_info = *current;
        http2_client_lifecycle_scratch_t *scratch = http2_client_lifecycle_mem();
        if (!scratch) {
            return;
        }
        scratch->lifecycle_key = http2_client_lifecycle_key(stream, prev_info->start_monotime_ns);
        scratch->terminal.end_monotime_ns = bpf_ktime_get_ns();
        bpf_probe_read(scratch->terminal.ret_data, sizeof(scratch->terminal.ret_data), u_buf);
        bpf_map_update_elem(
            &h2c_terminals, &scratch->lifecycle_key, &scratch->terminal, BPF_NOEXIST);
        bpf_tail_call_static(ctx, &jump_table, k_tail_protocol_http2_grpc_finish_client);
        return;
    }

    prev_info->end_monotime_ns = bpf_ktime_get_ns();
    bpf_dbg_printk("stream_id = %d", stream->stream_id);
    //dbg_print_http_connection_info(&stream->pid_conn.conn); // commented out since GitHub CI doesn't like this call

    http2_grpc_request_t *trace = bpf_ringbuf_reserve(&events, sizeof(http2_grpc_request_t), 0);
    if (trace) {
        bpf_probe_read(prev_info->ret_data, k_kprobes_http2_ret_buf_size, u_buf);
        __builtin_memcpy(trace, prev_info, sizeof(http2_grpc_request_t));
        bpf_ringbuf_submit(trace, get_flags());
    }
    bpf_map_delete_elem(&ongoing_http2_grpc, stream);
}

static __always_inline frame_header_t next_frame(const grpc_frames_ctx_t *g_ctx) {
    // read next frame
    const void *offset = (const unsigned char *)g_ctx->args.u_buf + g_ctx->pos;

    frame_header_t header = {};

    if (bpf_probe_read(&header, sizeof(header), offset) != 0) {
        bpf_dbg_printk("failed to read frame header");
        return header; // the caller will deal with an invalid header
    }

    header.length = bpf_ntohl(header.length << 8);
    header.stream_id = bpf_ntohl(header.stream_id << 1);

    //bpf_dbg_printk("http2 frame type = %u, len = %u", header.type, header.length);
    //bpf_dbg_printk("http2 frame stream_id = %u, flags = %u", header.stream_id, header.flags);

    return header;
}

static __always_inline void update_prev_info(grpc_frames_ctx_t *g_ctx) {
    if (g_ctx->has_prev_info) {
        return;
    }

    const http2_grpc_request_t *prev_info =
        bpf_map_lookup_elem(&ongoing_http2_grpc, &g_ctx->stream);

    if (prev_info) {
        g_ctx->prev_info = *prev_info;
        g_ctx->has_prev_info = 1;
    }
}

static __always_inline void reset_http2_stream_frame_context(grpc_frames_ctx_t *g_ctx) {
    g_ctx->has_prev_info = 0;
    g_ctx->found_data_frame = 0;
    g_ctx->saved_buf_pos = 0;
    g_ctx->saved_stream_id = 0;
    g_ctx->stream.stream_id = 0;
    g_ctx->server_tp_offset = 0;
    g_ctx->server_tp_encoded_len = 0;
    g_ctx->server_tp_huffman = 0;
    g_ctx->server_hpack_force_root = 0;
    g_ctx->server_hpack_maintenance = 0;
    g_ctx->server_hpack_cache_store_pending = 0;
    g_ctx->server_hpack_fail_closed = 0;
}

static __always_inline void fail_http2_server_coalesced_resume(grpc_frames_ctx_t *g_ctx) {
    if (!g_ctx || !g_ctx->server_hpack_resume_pending) {
        return;
    }
    // Never look up or poison by the current tuple alone: a failed tail call
    // can race a replacement generation. The captured key only invalidates
    // the generation whose trailing bytes were skipped.
    retire_http2_server_hpack_generation(&g_ctx->server_hpack_resume_key);
    g_ctx->terminate_search = 1;
    g_ctx->server_hpack_resume_pending = 0;
}

static __always_inline void resume_http2_server_coalesced_frames(void *ctx,
                                                                 grpc_frames_ctx_t *g_ctx) {
    if (!g_ctx || !g_ctx->server_hpack_resume_pending || g_ctx->pos >= g_ctx->args.bytes_len) {
        return;
    }
    http2_conn_info_data_t *connection = current_http2_connection(&g_ctx->stream.pid_conn);
    if (!http2_server_hpack_generation_matches(
            &g_ctx->server_hpack_resume_key, &g_ctx->stream.pid_conn, connection)) {
        // The bytes were observed under an old connection generation. Drop
        // them without revoking authority from the replacement generation.
        g_ctx->server_hpack_resume_pending = 0;
        return;
    }
    reset_http2_stream_frame_context(g_ctx);
    bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);
    fail_http2_server_coalesced_resume(g_ctx);
}

static __always_inline u8 http2_server_request_direction(const grpc_frames_ctx_t *g_ctx) {
    return g_ctx && request_type_by_direction(g_ctx->args.direction, PACKET_TYPE_REQUEST) ==
                        EVENT_HTTP_REQUEST;
}

static __always_inline http2_server_hpack_state_t *
begin_http2_server_cursor_update(grpc_frames_ctx_t *g_ctx) {
    http2_conn_info_data_t *connection = current_http2_connection(&g_ctx->stream.pid_conn);
    if (!connection || !begin_http2_server_hpack_transaction(g_ctx, connection)) {
        return NULL;
    }
    http2_server_hpack_state_t *state = owned_http2_server_hpack_state(g_ctx, NULL);
    if (!state) {
        (void)recover_http2_server_hpack_state(&g_ctx->server_hpack_lease_key);
        state = owned_http2_server_hpack_state(g_ctx, NULL);
    }
    return state;
}

static __always_inline void desync_http2_server_frame_observation(grpc_frames_ctx_t *g_ctx) {
    if (!http2_server_request_direction(g_ctx)) {
        return;
    }
    http2_server_hpack_state_t *state = begin_http2_server_cursor_update(g_ctx);
    if (state) {
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
    }
    release_http2_server_hpack_transaction(g_ctx);
}

static __always_inline u8 copy_http2_server_cursor_header(grpc_frames_ctx_t *g_ctx,
                                                          http2_server_hpack_state_t *state,
                                                          u32 buffer_pos,
                                                          u32 copy_len) {
    unsigned char *scratch = tp_char_buf_mem();
    if (!scratch || !copy_len || copy_len > k_h2_frame_header_len ||
        state->request_cursor.header_len > k_h2_frame_header_len ||
        copy_len > k_h2_frame_header_len - state->request_cursor.header_len) {
        return 0;
    }
    bpf_clamp_umax(copy_len, k_h2_frame_header_len);
    if (bpf_probe_read(scratch, copy_len, (const void *)(g_ctx->args.u_buf + buffer_pos)) != 0) {
        return 0;
    }

#pragma unroll
    for (u8 i = 0; i < k_h2_frame_header_len; i++) {
        if (i < copy_len) {
            u32 target = state->request_cursor.header_len + i;
            bpf_clamp_umax(target, k_h2_frame_header_len - 1);
            state->request_cursor.header[target] = scratch[i];
        }
    }
    state->request_cursor.header_len += copy_len;
    return 1;
}

static __always_inline u8 preserve_http2_server_partial_frame_header(grpc_frames_ctx_t *g_ctx,
                                                                     u32 buffer_pos,
                                                                     u32 remaining) {
    if (!http2_server_request_direction(g_ctx) || !remaining ||
        remaining >= k_h2_frame_header_len) {
        return 0;
    }
    http2_server_hpack_state_t *state = begin_http2_server_cursor_update(g_ctx);
    if (!state || h2_request_frame_cursor_active(&state->request_cursor) ||
        !copy_http2_server_cursor_header(g_ctx, state, buffer_pos, remaining)) {
        if (state) {
            state->desynced = 1;
            hpack_dynamic_name_state_invalidate(&state->dynamic);
        }
        release_http2_server_hpack_transaction(g_ctx);
        return 0;
    }
    release_http2_server_hpack_transaction(g_ctx);
    return 1;
}

static __always_inline u8 preserve_http2_server_partial_frame_payload(grpc_frames_ctx_t *g_ctx,
                                                                      u32 payload_remaining) {
    if (!http2_server_request_direction(g_ctx) || !payload_remaining) {
        return 0;
    }
    http2_server_hpack_state_t *state = begin_http2_server_cursor_update(g_ctx);
    if (!state || h2_request_frame_cursor_active(&state->request_cursor)) {
        if (state) {
            state->desynced = 1;
            hpack_dynamic_name_state_invalidate(&state->dynamic);
        }
        release_http2_server_hpack_transaction(g_ctx);
        return 0;
    }
    state->request_cursor.payload_remaining = payload_remaining;
    release_http2_server_hpack_transaction(g_ctx);
    return 1;
}

enum http2_server_cursor_resume_result : u8 {
    k_http2_server_cursor_absent,
    k_http2_server_cursor_pending,
    k_http2_server_cursor_frame_boundary,
};

static __noinline u8 resume_http2_server_frame_cursor(void *ctx,
                                                      grpc_frames_ctx_t *g_ctx,
                                                      http2_conn_info_data_t *connection) {
    if (!http2_server_request_direction(g_ctx) || !connection) {
        return k_http2_server_cursor_absent;
    }
    const http2_server_hpack_lease_key_t key =
        http2_server_hpack_lease_key(&g_ctx->stream.pid_conn, connection);
    http2_server_hpack_state_t *state = lookup_http2_server_hpack_state(&key);
    if (!state || !h2_request_frame_cursor_active(&state->request_cursor)) {
        return k_http2_server_cursor_absent;
    }
    if (!begin_http2_server_hpack_transaction(g_ctx, connection)) {
        return k_http2_server_cursor_pending;
    }
    state = owned_http2_server_hpack_state(g_ctx, NULL);
    if (!state) {
        release_http2_server_hpack_transaction(g_ctx);
        return k_http2_server_cursor_pending;
    }

    u32 pos = 0;
    const u32 available = g_ctx->args.bytes_len > 0 ? (u32)g_ctx->args.bytes_len : 0;
    if (state->request_cursor.payload_remaining) {
        const u32 skip = state->request_cursor.payload_remaining < available
                             ? state->request_cursor.payload_remaining
                             : available;
        state->request_cursor.payload_remaining -= skip;
        pos += skip;
        if (state->request_cursor.payload_remaining || pos == available) {
            release_http2_server_hpack_transaction(g_ctx);
            return k_http2_server_cursor_pending;
        }
    }

    if (state->request_cursor.header_len) {
        const u32 needed = k_h2_frame_header_len - state->request_cursor.header_len;
        const u32 remaining = available - pos;
        const u32 take = needed < remaining ? needed : remaining;
        if (take && !copy_http2_server_cursor_header(g_ctx, state, pos, take)) {
            state->desynced = 1;
            hpack_dynamic_name_state_invalidate(&state->dynamic);
            h2_request_frame_cursor_reset(&state->request_cursor);
            release_http2_server_hpack_transaction(g_ctx);
            return k_http2_server_cursor_pending;
        }
        pos += take;
        if (state->request_cursor.header_len < k_h2_frame_header_len) {
            release_http2_server_hpack_transaction(g_ctx);
            return k_http2_server_cursor_pending;
        }

        const u32 frame_length = h2_raw_frame_length(state->request_cursor.header);
        const u8 frame_type = state->request_cursor.header[3];
        const u8 frame_flags = state->request_cursor.header[4];
        const u32 stream_id = h2_raw_frame_stream_id(state->request_cursor.header);
        if (!h2_tracked_frame_stream_valid(frame_type, stream_id)) {
            state->desynced = 1;
            hpack_dynamic_name_state_invalidate(&state->dynamic);
        }

        if (frame_type == k_h2_frame_headers) {
            g_ctx->stream.stream_id = stream_id;
            update_prev_info(g_ctx);
            const u8 maintenance =
                g_ctx->has_prev_info || ((frame_flags & k_h2_flag_end_stream) && frame_length <= 2);
            h2_hpack_stream_begin(&state->headers, g_ctx->args.direction);
            state->headers.maintenance = maintenance;
            g_ctx->server_hpack_maintenance = maintenance;
            g_ctx->saved_stream_id = stream_id;
            g_ctx->saved_buf_pos = pos;

            u16 consumed = 0;
            h2_hpack_stream_consume(
                &state->headers, state->request_cursor.header, k_h2_frame_header_len, &consumed);
            h2_request_frame_cursor_reset(&state->request_cursor);
            if (consumed != k_h2_frame_header_len || state->headers.framing_invalid) {
                state->desynced = 1;
                hpack_dynamic_name_state_invalidate(&state->dynamic);
            }

            u8 result = state->headers.complete ? k_http2_server_header_complete
                                                : k_http2_server_header_pending;
            if (pos < available && !state->headers.complete) {
                result = consume_http2_server_header_bytes(g_ctx, state, pos);
            }
            if (result == k_http2_server_header_pending) {
                preserve_http2_server_header_fragment(g_ctx);
                return k_http2_server_cursor_pending;
            }
            if (result == k_http2_server_header_failed) {
                abort_http2_server_hpack_transaction(g_ctx, 1);
                return k_http2_server_cursor_pending;
            }
            if (maintenance) {
                bpf_tail_call(
                    ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server);
            } else {
                bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame);
            }
            abort_http2_server_hpack_transaction(g_ctx, 1);
            return k_http2_server_cursor_pending;
        }

        if (frame_type == k_h2_frame_continuation) {
            state->desynced = 1;
            hpack_dynamic_name_state_invalidate(&state->dynamic);
        }
        state->request_cursor.header_len = 0;
        state->request_cursor.payload_remaining = frame_length;
    }

    if (state->request_cursor.payload_remaining) {
        const u32 remaining = available - pos;
        const u32 skip = state->request_cursor.payload_remaining < remaining
                             ? state->request_cursor.payload_remaining
                             : remaining;
        state->request_cursor.payload_remaining -= skip;
        pos += skip;
        if (state->request_cursor.payload_remaining || pos == available) {
            release_http2_server_hpack_transaction(g_ctx);
            return k_http2_server_cursor_pending;
        }
    }

    g_ctx->pos = pos;
    release_http2_server_hpack_transaction(g_ctx);
    return k_http2_server_cursor_frame_boundary;
}

static __always_inline int
handle_headers_frame(void *ctx, grpc_frames_ctx_t *g_ctx, const frame_header_t *frame) {
    if (g_ctx->stream.stream_id != frame->stream_id) {
        g_ctx->has_prev_info = 0;
        g_ctx->found_data_frame = 0;
        g_ctx->saved_stream_id = 0;
    }
    g_ctx->stream.stream_id = frame->stream_id;

    // if we don't have prev_info, try looking it up...
    update_prev_info(g_ctx);

    const u8 server_request =
        request_type_by_direction(g_ctx->args.direction, PACKET_TYPE_REQUEST) ==
            EVENT_HTTP_REQUEST &&
        (!g_ctx->has_prev_info || g_ctx->prev_info.type == EVENT_HTTP_REQUEST);
    if (server_request) {
        const u8 maintenance =
            g_ctx->has_prev_info || (is_flags_only_frame(frame) && http_grpc_stream_ended(frame));
        http2_conn_info_data_t *connection = current_http2_connection(&g_ctx->stream.pid_conn);
        if (!connection || !begin_http2_server_hpack_transaction(g_ctx, connection)) {
            return 0;
        }
        http2_server_hpack_state_t *state = owned_http2_server_hpack_state(g_ctx, NULL);
        if (!state) {
            (void)recover_http2_server_hpack_state(&g_ctx->server_hpack_lease_key);
            state = owned_http2_server_hpack_state(g_ctx, NULL);
            if (!state) {
                abort_http2_server_hpack_transaction(g_ctx, 1);
                return 0;
            }
        }
        if (state->headers.active) {
            abort_http2_server_hpack_transaction(g_ctx, 1);
            return 0;
        }
        if (g_ctx->server_hpack_blocks >= k_h2_max_coalesced_header_blocks) {
            abort_http2_server_hpack_transaction(g_ctx, 1);
            g_ctx->terminate_search = 1;
            return 0;
        }
        h2_hpack_stream_begin(&state->headers, g_ctx->args.direction);
        state->headers.maintenance = maintenance;
        g_ctx->server_hpack_maintenance = maintenance;
        g_ctx->saved_stream_id = frame->stream_id;
        g_ctx->saved_buf_pos = g_ctx->pos;

        const u8 result = consume_http2_server_header_bytes(g_ctx, state, (u32)g_ctx->pos);
        if (result == k_http2_server_header_pending) {
            preserve_http2_server_header_fragment(g_ctx);
            return 0;
        }
        if (result == k_http2_server_header_failed) {
            abort_http2_server_hpack_transaction(g_ctx, 1);
            return 0;
        }
        if (maintenance) {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server);
        } else {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame);
        }
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }

    if (g_ctx->has_prev_info) {
        g_ctx->saved_stream_id = g_ctx->stream.stream_id;
        g_ctx->saved_buf_pos = g_ctx->pos;

        if (http_grpc_stream_ended(frame)) {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_end_frame);
            return 0; // normally unreachable
        }
    } else {
        // Not starting new grpc request, found end frame in a start, likely
        // just terminating prev connection
        if (!(is_flags_only_frame(frame) && http_grpc_stream_ended(frame))) {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame);
            return 0; // normally unreachable
        }
    }

    return 1;
}

static __always_inline void handle_data_frame(void *ctx, grpc_frames_ctx_t *g_ctx) {
    if (!g_ctx->has_prev_info || !g_ctx->saved_stream_id) {
        // we haven't found anything useful...
        return;
    }

    const u8 type = g_ctx->prev_info.type;
    const u8 direction = g_ctx->args.direction;

    if (g_ctx->found_data_frame || ((type == EVENT_HTTP_REQUEST) && (direction == TCP_SEND)) ||
        ((type == EVENT_HTTP_CLIENT) && (direction == TCP_RECV))) {

        g_ctx->stream.pid_conn = g_ctx->args.pid_conn;
        g_ctx->stream.stream_id = g_ctx->saved_stream_id;

        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_end_frame);
    }
}

// k_tail_protocol_http2_grpc_handle_start_frame
SEC("kprobe/http2")
int obi_protocol_http2_grpc_handle_start_frame(void *ctx) {
    (void)ctx;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    const call_protocol_args_t *args = &g_ctx->args;

    void *offset = (unsigned char *)args->u_buf + g_ctx->pos;

    http2_grpc_start(
        ctx, &g_ctx->stream, offset, args->bytes_len, args->direction, args->ssl, args->orig_dport);

    return 0;
}

SEC("kprobe/http2")
int obi_protocol_http2_grpc_finish_client(void *ctx) {
    (void)ctx;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    http2_grpc_request_t *request = http2_info_mem();
    http2_client_lifecycle_scratch_t *scratch = http2_client_lifecycle_mem();
    if (!g_ctx || !request || !scratch) {
        return 0;
    }

    http2_grpc_request_t *base = bpf_map_lookup_elem(&ongoing_http2_grpc, &g_ctx->stream);
    if (!base || base->type != EVENT_HTTP_CLIENT) {
        return 0;
    }

    scratch->lifecycle_key = http2_client_lifecycle_key(&g_ctx->stream, base->start_monotime_ns);
    finish_h2_client_if_terminal(&g_ctx->stream, &scratch->lifecycle_key, request);
    return 0;
}

// SERVER tail call: HPACK parse first (per-stream, no trace_map race), per-conn
// fallback if missed. The connection accumulator has already reconstructed
// HEADERS/CONTINUATION bytes across callbacks under the generation lease.
SEC("kprobe/http2")
int obi_protocol_http2_grpc_handle_start_frame_server(void *ctx) {
    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    if (!g_ctx) {
        return 0;
    }

    g_ctx->server_hpack_base = 0;
    __builtin_memset(&g_ctx->server_hpack_decoder, 0, sizeof(g_ctx->server_hpack_decoder));

    unsigned char *scan = tp_char_buf_mem();
    http2_server_hpack_lease_t *lease = NULL;
    http2_server_hpack_state_t *state = owned_http2_server_hpack_state(g_ctx, &lease);
    if (!scan || !state || !lease || !state->headers.complete) {
        abort_http2_server_hpack_transaction(g_ctx, 1);
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
        return 0;
    }

    if (lease->poisoned || state->desynced || state->headers.invalid) {
        if (lease->poisoned) {
            state->desynced = 1;
        }
        hpack_dynamic_name_state_invalidate(&state->dynamic);
        if (g_ctx->server_hpack_maintenance) {
            bpf_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        }
        tp_info_pid_t *tp_p = tp_info_mem();
        if (tp_p) {
            g_ctx->server_hpack_fail_closed = 1;
            apply_fail_closed_sampler_result(&tp_p->tp);
            bpf_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        }
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }

    __builtin_memcpy(scan, state->headers.block, k_hpack_tp_max_scan);
    hpack_traceparent_scan_init(&g_ctx->server_hpack_scan, state->headers.block_len, 1);

    bpf_tail_call_static(ctx, &jump_table, k_tail_protocol_http2_grpc_parse_server_headers);
    discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
    abort_http2_server_hpack_transaction(g_ctx, 1);
    return 0;
}

SEC("kprobe/http2")
int obi_protocol_http2_grpc_parse_server_headers(void *ctx) {
    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    if (!g_ctx) {
        return 0;
    }
    unsigned char *scan = tp_char_buf_mem();
    http2_server_hpack_lease_t *lease = NULL;
    http2_server_hpack_state_t *state = owned_http2_server_hpack_state(g_ctx, &lease);
    if (!state || !lease) {
        release_http2_server_hpack_transaction(g_ctx);
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
        resume_http2_server_coalesced_frames(ctx, g_ctx);
        return 0;
    }
    if (!scan || lease->poisoned || state->desynced) {
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
        if (g_ctx->server_hpack_maintenance) {
            bpf_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        }
        tp_info_pid_t *tp_p = tp_info_mem();
        if (tp_p) {
            g_ctx->server_hpack_fail_closed = 1;
            apply_fail_closed_sampler_result(&tp_p->tp);
            discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
            bpf_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        }
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }
    if (!g_ctx->server_hpack_scan.done) {
        u32 base = g_ctx->server_hpack_base;
        bpf_clamp_umax(base, k_kprobes_http2_buf_size - 1);

#pragma clang loop unroll(disable)
        for (u8 step = 0; step < k_h2_hpack_parse_steps_per_call; step++) {
            if (hpack_traceparent_scan_step(
                    &scan[base], &g_ctx->server_hpack_scan, &state->dynamic)) {
                break;
            }
        }
    }

    if (!g_ctx->server_hpack_scan.done) {
        bpf_tail_call_static(ctx, &jump_table, k_tail_protocol_http2_grpc_parse_server_headers);
        hpack_traceparent_scan_fail(&g_ctx->server_hpack_scan);
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
    } else if (g_ctx->server_hpack_scan.dynamic_invalid) {
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
    }

    const hpack_traceparent_result_t result =
        hpack_traceparent_scan_result(&g_ctx->server_hpack_scan);
    if (result.value_cache_unavailable) {
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
    }
    if (state->desynced) {
        if (g_ctx->server_hpack_maintenance) {
            bpf_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        }
        tp_info_pid_t *fail_closed_tp = tp_info_mem();
        if (fail_closed_tp) {
            g_ctx->server_hpack_fail_closed = 1;
            apply_fail_closed_sampler_result(&fail_closed_tp->tp);
            discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
            bpf_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        }
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }

    const u8 maintenance_cache_fill =
        g_ctx->server_hpack_maintenance && result.status == k_hpack_traceparent_found &&
        !result.value_cached && result.inserted_identity_valid &&
        result.value_offset < k_hpack_tp_max_scan && result.encoded_value_len;
    if (g_ctx->server_hpack_maintenance && !maintenance_cache_fill) {
        bpf_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }

    tp_info_pid_t *tp_p = tp_info_mem();
    if (!tp_p) {
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }
    if (result.status == k_hpack_traceparent_found && result.value_cached) {
        __builtin_memcpy(tp_p->tp.trace_id, result.cached_trace_id, TRACE_ID_SIZE_BYTES);
        __builtin_memcpy(tp_p->tp.parent_id, result.cached_parent_id, SPAN_ID_SIZE_BYTES);
        tp_p->tp.flags = result.cached_flags;
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
        bpf_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }
    if (result.status == k_hpack_traceparent_found && result.value_offset < k_hpack_tp_max_scan &&
        result.encoded_value_len) {
        g_ctx->server_tp_offset = g_ctx->server_hpack_base + result.value_offset;
        g_ctx->server_tp_encoded_len = result.encoded_value_len;
        g_ctx->server_tp_huffman = result.value_huffman;
        g_ctx->server_hpack_inserted_slot = result.inserted_slot;
        g_ctx->server_hpack_inserted_generation = result.inserted_generation;
        g_ctx->server_hpack_cache_store_pending = result.inserted_identity_valid;
        bpf_tail_call_static(
            ctx, &jump_table, k_tail_protocol_http2_grpc_validate_server_traceparent);
    }

    if (g_ctx->server_hpack_maintenance) {
        bpf_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }

    if (hpack_server_parent_authority(result.status, 0) ==
        k_hpack_server_parent_connection_fallback) {
        find_trace_for_server_request(&g_ctx->stream.pid_conn.conn, &tp_p->tp, EVENT_HTTP_REQUEST);
    } else {
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
    }
    bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
    abort_http2_server_hpack_transaction(g_ctx, 1);
    return 0;
}

SEC("kprobe/http2")
int obi_protocol_http2_grpc_validate_server_traceparent(void *ctx) {
    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    if (!g_ctx) {
        return 0;
    }
    tp_info_pid_t *tp_p = tp_info_mem();
    if (!tp_p) {
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }
    http2_server_hpack_lease_t *lease = NULL;
    http2_server_hpack_state_t *state = owned_http2_server_hpack_state(g_ctx, &lease);
    if (!state || !lease) {
        release_http2_server_hpack_transaction(g_ctx);
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
        resume_http2_server_coalesced_frames(ctx, g_ctx);
        return 0;
    }
    if (lease->poisoned || state->desynced) {
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
        g_ctx->server_hpack_fail_closed = 1;
        apply_fail_closed_sampler_result(&tp_p->tp);
        bpf_memset(tp_p->tp.trace_id, 0, sizeof(tp_p->tp.trace_id));
        bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
        if (g_ctx->server_hpack_maintenance) {
            bpf_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        }
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
        bpf_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }
    unsigned char *scan = tp_char_buf_mem();
    if (!scan) {
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
        g_ctx->server_hpack_fail_closed = 1;
        apply_fail_closed_sampler_result(&tp_p->tp);
        if (g_ctx->server_hpack_maintenance) {
            bpf_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        }
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
        bpf_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }

    u32 offset = g_ctx->server_tp_offset;
    u32 encoded_len = g_ctx->server_tp_encoded_len;
    if (offset < k_kprobes_http2_buf_size && encoded_len &&
        encoded_len <= k_kprobes_http2_buf_size - offset) {
        bpf_clamp_umax(offset, k_kprobes_http2_buf_size - 1);
        bpf_clamp_umax(encoded_len, k_hpack_tp_max_scan);

        if (!g_ctx->server_hpack_decoder.initialized) {
            hpack_traceparent_decoder_init(
                &g_ctx->server_hpack_decoder, encoded_len, g_ctx->server_tp_huffman, 1, &tp_p->tp);
        }

        if (!g_ctx->server_hpack_decoder.done) {
#pragma clang loop unroll(disable)
            for (u8 step = 0; step < k_h2_hpack_decode_steps_per_call; step++) {
                if (hpack_traceparent_decoder_step(
                        &scan[offset], &g_ctx->server_hpack_decoder, &tp_p->tp)) {
                    break;
                }
            }
        }

        if (!g_ctx->server_hpack_decoder.done) {
            bpf_tail_call_static(
                ctx, &jump_table, k_tail_protocol_http2_grpc_validate_server_traceparent);
            g_ctx->server_hpack_decoder.value.valid_base = 0;
            hpack_traceparent_decoder_finish(&g_ctx->server_hpack_decoder, &tp_p->tp);
        }
    }

    if (g_ctx->server_hpack_cache_store_pending) {
        if (g_ctx->server_hpack_decoder.valid) {
            const u8 stored =
                hpack_dynamic_store_traceparent(&state->dynamic,
                                                g_ctx->server_hpack_inserted_slot,
                                                g_ctx->server_hpack_inserted_generation,
                                                &tp_p->tp);
            if (!stored) {
                state->desynced = 1;
                hpack_dynamic_name_state_invalidate(&state->dynamic);
            }
        }
        g_ctx->server_hpack_cache_store_pending = 0;
    }

    if (state->desynced) {
        g_ctx->server_hpack_fail_closed = 1;
        apply_fail_closed_sampler_result(&tp_p->tp);
        if (g_ctx->server_hpack_maintenance) {
            bpf_tail_call(
                ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        }
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
        bpf_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }

    if (g_ctx->server_hpack_maintenance) {
        bpf_tail_call(
            ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }
    discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);

    bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server_commit);
    abort_http2_server_hpack_transaction(g_ctx, 1);
    return 0;
}

// SERVER commit: shared post-branch — new_trace_id if missing, commit tp,
// set_trace_info_for_connection, server_or_client_trace, server_traces,
// ongoing_http2_grpc.
SEC("kprobe/http2")
int obi_protocol_http2_grpc_handle_start_frame_server_commit(void *ctx) {
    (void)ctx;
    grpc_frames_ctx_t *g_ctx = grpc_ctx();
    if (!g_ctx) {
        return 0;
    }
    http2_server_hpack_lease_t *lease = NULL;
    http2_server_hpack_state_t *state = owned_http2_server_hpack_state(g_ctx, &lease);
    if (!state || !lease) {
        release_http2_server_hpack_transaction(g_ctx);
        discard_trace_for_server_request(&g_ctx->stream.pid_conn.conn);
        resume_http2_server_coalesced_frames(ctx, g_ctx);
        return 0;
    }
    if (g_ctx->server_hpack_maintenance) {
        const u8 end_stream = state->headers.end_stream;
        if (lease->poisoned || state->desynced) {
            state->desynced = 1;
            hpack_dynamic_name_state_invalidate(&state->dynamic);
        }
        h2_hpack_stream_reset(&state->headers);
        release_http2_server_hpack_transaction(g_ctx);

        if (end_stream) {
            g_ctx->stream.stream_id = g_ctx->saved_stream_id;
            update_prev_info(g_ctx);
            if (g_ctx->has_prev_info) {
                bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_end_frame);
                fail_http2_server_coalesced_resume(g_ctx);
                return 0;
            }
        }
        resume_http2_server_coalesced_frames(ctx, g_ctx);
        return 0;
    }

    http2_grpc_request_t *h2g_info = http2_info_mem();
    if (!h2g_info) {
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }
    tp_info_pid_t *tp_p = tp_info_mem();
    if (!tp_p) {
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }
    if (lease->poisoned || state->desynced || g_ctx->server_hpack_fail_closed) {
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
        apply_fail_closed_sampler_result(&tp_p->tp);
        bpf_memset(tp_p->tp.trace_id, 0, sizeof(tp_p->tp.trace_id));
        bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    } else if (g_ctx->server_hpack_force_root) {
        bpf_memset(tp_p->tp.trace_id, 0, sizeof(tp_p->tp.trace_id));
        bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    }

    const u8 found_tp = valid_trace(tp_p->tp.trace_id);
    http2_grpc_start_finalize_server(
        &g_ctx->stream, h2g_info, tp_p, found_tp, g_ctx->args.ssl, g_ctx->args.orig_dport);

    h2_hpack_stream_reset(&state->headers);
    release_http2_server_hpack_transaction(g_ctx);

    resume_http2_server_coalesced_frames(ctx, g_ctx);

    return 0;
}

// k_tail_protocol_http2_grpc_handle_end_frame
SEC("kprobe/http2")
int obi_protocol_http2_grpc_handle_end_frame(void *ctx) {
    (void)ctx;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    const u8 req_type = request_type_by_direction(g_ctx->args.direction, PACKET_TYPE_RESPONSE);

    if (req_type == g_ctx->prev_info.type) {
        u32 buf_pos = g_ctx->saved_buf_pos;

        bpf_clamp_umax(buf_pos, k_iovec_max_len);

        void *offset = (unsigned char *)g_ctx->args.u_buf + buf_pos;
        http2_grpc_end(ctx, &g_ctx->stream, &g_ctx->prev_info, offset);

        bpf_map_delete_elem(&active_ssl_connections, &g_ctx->args.pid_conn);
    } else {
        // Wrong-direction end flag (e.g. a CLIENT request's own HEADERS
        // carries END_STREAM=1). Keep ongoing_http2_grpc so the correct
        // -direction end can fire later (response trailers for CLIENT,
        // request send for SERVER).
        bpf_dbg_printk("grpc request/response mismatch, req_type %d, prev_info->type %d",
                       req_type,
                       g_ctx->prev_info.type);
    }

    resume_http2_server_coalesced_frames(ctx, g_ctx);

    return 0;
}

// k_tail_protocol_http2_grpc_frames
// this function scans a raw buffer and tries to find GRPC frames on it
// (represented by 'frame_header_t'). We care about 3 kinds of frames: start
// frames, end frames and data frames. Start and end frames are used as anchor
// points to determine the lifespan of a GRPC connection, and the data frames
// are used as a fallback mechanism in case those are found. We use that
// information to evaluate whether the parsed data is potentially a GRPC
// frame, and if so, we ship it to userspace for further processing.
SEC("kprobe/http2")
int obi_protocol_http2_grpc_frames(void *ctx) {
    const u8 k_max_loop_iterations = 4; // the maximum number of the for loop iterations
    const u8 k_loop_count = 3;          // the number of times we will retry the loop
    const u8 k_iterations = k_max_loop_iterations * k_loop_count;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    // A successful commit-to-frames tail call lands here. Clearing the flag
    // in the callee preserves it in the caller when the tail call itself
    // fails, allowing that caller to invalidate the captured generation.
    g_ctx->server_hpack_resume_pending = 0;

    // this loop will effectively run for k_iterations, split between the
    // unrolled for loop and the tail call (see comment after the loop)
    for (u8 i = 0; i < k_max_loop_iterations; ++i) {
        g_ctx->iterations++;

        if (g_ctx->pos >= g_ctx->args.bytes_len) {
            break;
        }

        const u32 remaining = (u32)(g_ctx->args.bytes_len - g_ctx->pos);
        if (remaining < k_frame_header_len) {
            (void)preserve_http2_server_partial_frame_header(g_ctx, (u32)g_ctx->pos, remaining);
            g_ctx->terminate_search = 1;
            break;
        }

        const frame_header_t frame = next_frame(g_ctx);

        // if handle_headers_frame returns 0, it means bpf_tail_call has
        // failed and something is very wrong, so we just bail...
        if (is_headers_frame(&frame) && !handle_headers_frame(ctx, g_ctx, &frame)) {
            //bpf_dbg_printk("http2 bpf_tail_call failed");
            return 0;
        }

        if (is_data_frame(&frame)) {
            g_ctx->found_data_frame = 1;
        }

        if (!h2_tracked_frame_stream_valid(frame.type, frame.stream_id) ||
            frame.type == FrameContinuation) {
            desync_http2_server_frame_observation(g_ctx);
            g_ctx->terminate_search = 1;
            //bpf_dbg_printk("Invalid frame, terminating search");
            break;
        }

        const u32 framed_len = frame.length + k_frame_header_len;
        if (framed_len > remaining) {
            const u32 observed_payload = remaining - k_frame_header_len;
            (void)preserve_http2_server_partial_frame_payload(g_ctx,
                                                              frame.length - observed_payload);
            g_ctx->terminate_search = 1;
            //bpf_dbg_printk("Frame length bigger than bytes len");
            break;
        }

        g_ctx->pos += framed_len;
        if (g_ctx->pos >= g_ctx->args.bytes_len) {
            break;
        }
        //bpf_dbg_printk("New buf read g_ctx.pos = %d", g_ctx->pos);
    }

    // this is a weird recursion - we can't loop many times above because the
    // verifier will reject this program as too complex, we don't want to use
    // bpf_loop() as we need to support kernels < 5.17, and finally we don't
    // want to abuse bpf_tail_call as things can get slow (and limited), so we
    // use this mirror-cracking hybrid approach
    if (!g_ctx->terminate_search && g_ctx->iterations < k_iterations) {
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);
        desync_http2_server_frame_observation(g_ctx);
        return 0; // unreachable, but bail safely if bpf_tail_call fails
    }

    if (!g_ctx->terminate_search && g_ctx->pos < g_ctx->args.bytes_len) {
        desync_http2_server_frame_observation(g_ctx);
    }

    // We only loop N times looking for the stream termination. If the data
    // packed is large we'll miss the frame saying the stream closed. In that
    // case we try this backup path, which will tail call on success.
    handle_data_frame(ctx, g_ctx);

    return 0;
}

// k_tail_protocol_http2
SEC("kprobe/http2")
int obi_protocol_http2(void *ctx) {
    call_protocol_args_t *args = protocol_args();

    if (!args) {
        return 0;
    }

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    __builtin_memset(g_ctx, 0, sizeof(*g_ctx));
    g_ctx->args = *args;
    g_ctx->stream.pid_conn = args->pid_conn;

    http2_conn_info_data_t *connection = current_http2_connection(&g_ctx->stream.pid_conn);
    const u8 cursor_result = resume_http2_server_frame_cursor(ctx, g_ctx, connection);
    if (cursor_result == k_http2_server_cursor_pending) {
        return 0;
    }
    if (cursor_result == k_http2_server_cursor_frame_boundary) {
        bpf_tail_call_static(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);
        desync_http2_server_frame_observation(g_ctx);
        return 0;
    }

    const http2_server_hpack_lease_key_t state_key =
        http2_server_hpack_lease_key(&g_ctx->stream.pid_conn, connection);
    http2_server_hpack_state_t *state = lookup_http2_server_hpack_state(&state_key);
    if (connection && state && state->headers.active &&
        state->headers.direction == args->direction &&
        request_type_by_direction(args->direction, PACKET_TYPE_REQUEST) == EVENT_HTTP_REQUEST) {
        if (!begin_http2_server_hpack_transaction(g_ctx, connection)) {
            return 0;
        }
        state = owned_http2_server_hpack_state(g_ctx, NULL);
        if (!state) {
            abort_http2_server_hpack_transaction(g_ctx, 1);
            return 0;
        }
        g_ctx->server_hpack_maintenance = state->headers.maintenance;
        const u8 result = consume_http2_server_header_bytes(g_ctx, state, 0);
        if (result == k_http2_server_header_pending) {
            preserve_http2_server_header_fragment(g_ctx);
            return 0;
        }
        if (result == k_http2_server_header_failed) {
            abort_http2_server_hpack_transaction(g_ctx, 1);
            return 0;
        }
        g_ctx->saved_stream_id = g_ctx->stream.stream_id;
        g_ctx->saved_buf_pos = 0;
        if (g_ctx->server_hpack_maintenance) {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame_server);
        } else {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame);
        }
        abort_http2_server_hpack_transaction(g_ctx, 1);
        return 0;
    }

    bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);

    desync_http2_server_frame_observation(g_ctx);

    return 0;
}
