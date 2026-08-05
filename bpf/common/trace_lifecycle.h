// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "common/lw_thread.h"
#include <bpfcore/utils.h>

#include <common/event_defs.h>
#include <common/outgoing_trace_handoff.h>
#include <common/runtime.h>
#include <common/trace_key.h>
#include <common/tracing.h>

#include <maps/cp_support_connect_info.h>
#include <maps/incoming_trace_map.h>
#include <maps/java_vt_threads.h>
#include <maps/outgoing_trace_map.h>
#include <maps/server_traces.h>

#include <gotracer/go_common.h>

#include <shared/obi_ctx.h>

static __always_inline u8 obi_ctx_matches_trace(const obi_ctx_info_t *obi, const tp_info_t *trace) {
    return obi && trace && bpf_memcmp(obi->trace_id, trace->trace_id, sizeof(obi->trace_id)) == 0 &&
           bpf_memcmp(obi->span_id, trace->span_id, sizeof(obi->span_id)) == 0;
}

static __always_inline void delete_server_trace_for_owner(pid_connection_info_t *pid_conn,
                                                          trace_key_t *t_key,
                                                          u64 owner_pid_tgid,
                                                          const tp_info_t *expected) {
    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_SERVER);
    int res = bpf_map_delete_elem(&server_traces, t_key);
    bpf_dbg_printk("Deleting server span for id=%llx, pid=%d, ns=%x",
                   bpf_get_current_pid_tgid(),
                   t_key->p_key.pid,
                   t_key->p_key.ns);
    bpf_dbg_printk("Deleting server span for res=%d", res);
    if (!(t_key->p_key.tid & JAVA_VT_TID_FLAG)) {
        obi_ctx_info_t *current_obi = bpf_map_lookup_elem(&traces_ctx_v1, &owner_pid_tgid);
        u8 *current_flags = bpf_map_lookup_elem(&traces_ctx_flags, &owner_pid_tgid);
        if (expected && obi_ctx_matches_trace(current_obi, expected) && current_flags &&
            *current_flags == expected->flags) {
            obi_ctx__del(owner_pid_tgid);
        }
    }
}

static __always_inline void delete_server_trace(pid_connection_info_t *pid_conn,
                                                trace_key_t *t_key) {
    tp_info_t expected = {};
    tp_info_pid_t *published = bpf_map_lookup_elem(&server_traces, t_key);
    if (published) {
        expected = published->tp;
    }
    delete_server_trace_for_owner(
        pid_conn, t_key, bpf_get_current_pid_tgid(), published ? &expected : NULL);
}

static __always_inline void delete_client_trace_info(pid_connection_info_t *pid_conn) {
    bpf_dbg_printk("Deleting client trace map for connection, pid=%d", pid_conn->pid);
    dbg_print_http_connection_info(&pid_conn->conn);

    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_CLIENT);
    bpf_map_delete_elem(&cp_support_connect_info, pid_conn);
}

static __always_inline void discard_trace_for_server_request(connection_info_t *conn) {
    connection_info_t sorted_conn = *conn;
    sort_connection_info(&sorted_conn);
    bpf_map_delete_elem(&incoming_trace_map, &sorted_conn);
    delete_trace_info_for_connection(conn, TRACE_TYPE_CLIENT);
}

static __always_inline u8 find_trace_for_server_request(connection_info_t *conn,
                                                        tp_info_t *tp,
                                                        const u8 type) {
    u8 found_tp = 0;
    connection_info_t sorted_conn = *conn;
    sort_connection_info(&sorted_conn);
    tp_info_pid_t *existing_tp = bpf_map_lookup_elem(&incoming_trace_map, &sorted_conn);
    if (existing_tp) {
        found_tp = 1;
        bpf_dbg_printk("Found incoming (TCP/IP) tp for server request");
        __builtin_memcpy(tp->trace_id, existing_tp->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, existing_tp->tp.span_id, sizeof(tp->parent_id));
        inherit_parent_sampling_state(tp, &existing_tp->tp);
        bpf_map_delete_elem(&incoming_trace_map, &sorted_conn);
    } else {
        bpf_dbg_printk("Looking up tracemap for");
        dbg_print_http_connection_info(conn);

        existing_tp = trace_info_for_connection(conn, TRACE_TYPE_CLIENT);

        bpf_dbg_printk("existing_tp=%llx", existing_tp);

        if (!disable_black_box_cp && correlated_requests(tp, existing_tp)) {
            if (existing_tp->valid) {
                bpf_dbg_printk("Found existing correlated tp for server request");
                // Mark the client info as invalid (used), in case the client
                // request information is not cleaned up.
                if ((type == EVENT_HTTP_REQUEST && existing_tp->req_type == EVENT_HTTP_CLIENT) ||
                    (type == EVENT_TCP_REQUEST && existing_tp->req_type == EVENT_TCP_REQUEST)) {
                    found_tp = 1;
                    __builtin_memcpy(tp->trace_id, existing_tp->tp.trace_id, sizeof(tp->trace_id));
                    __builtin_memcpy(tp->parent_id, existing_tp->tp.span_id, sizeof(tp->parent_id));
                    inherit_parent_sampling_state(tp, &existing_tp->tp);
                    // We ensure that server requests match the client type, otherwise SSL
                    // can often be confused with TCP.
                    existing_tp->valid = 0;
                    set_trace_info_for_connection(conn, TRACE_TYPE_CLIENT, existing_tp);
                    bpf_dbg_printk("setting the client info as used");
                } else {
                    bpf_dbg_printk("incompatible trace info, not using the correlated tp, type=%d, "
                                   "other type=%d",
                                   type,
                                   existing_tp->req_type);
                }
            } else {
                bpf_dbg_printk("the existing client tp was already used, ignoring");
            }
        }
    }

    return found_tp;
}

static __always_inline long
refresh_server_trace_publications(const connection_info_t *conn,
                                  const connection_info_part_t *server_conn_part,
                                  const tp_info_pid_t *tp_p,
                                  u32 host_pid,
                                  u64 owner_pid_tgid,
                                  lw_thread_t owner_lw_thread,
                                  u8 vt_keyed) {
    if (bpf_map_update_elem(&server_traces_aux, server_conn_part, tp_p, BPF_ANY) != 0 ||
        try_set_trace_info_for_connection(conn, TRACE_TYPE_SERVER, tp_p) != 0) {
        return -1;
    }

    if (!vt_keyed && obi_ctx__set(owner_pid_tgid, &tp_p->tp) != 0) {
        return -1;
    }

    if (owner_lw_thread != k_lw_thread_none) {
        go_addr_key_t g_key = {};
        go_addr_key_from_id_and_pid(&g_key, (void *)owner_lw_thread, host_pid);
        if (push_go_trace(&g_key, &tp_p->tp) != 0) {
            return -1;
        }
    }
    return 0;
}

typedef struct client_trace_publication_transaction {
    tp_info_pid_t previous_outgoing;
    tp_info_pid_t previous_trace;
    obi_ctx_info_t previous_obi;
    tp_info_pid_t published_outgoing;
    obi_ctx_info_t published_obi;
    u8 previous_flags;
    u8 outgoing_present;
    u8 trace_present;
    u8 obi_present;
    u8 flags_present;
    u8 outgoing_updated;
    u8 trace_updated;
    u8 obi_updated;
    u8 flags_updated;
    u8 connection_claim_acquired;
    u8 _pad[6];
} client_trace_publication_transaction_t;

typedef struct client_trace_publication_target {
    u64 owner_pid_tgid;
    u32 host_pid;
    u32 stream_id;
    u8 ssl;
    u8 vt_keyed;
    u8 connection_claim_preheld;
    u8 outgoing_noexist;
    u8 _pad[4];
} client_trace_publication_target_t;

static __always_inline void client_trace_publication_values(const tp_info_pid_t *tp_p,
                                                            u32 host_pid,
                                                            u8 ssl,
                                                            tp_info_pid_t *outgoing,
                                                            obi_ctx_info_t *obi_info) {
    *outgoing = *tp_p;
    outgoing->pid = host_pid;
    if (ssl) {
        outgoing->valid = 0;
    }

    bpf_memcpy(obi_info->trace_id, tp_p->tp.trace_id, sizeof(obi_info->trace_id));
    bpf_memcpy(obi_info->span_id, tp_p->tp.span_id, sizeof(obi_info->span_id));
}

static __always_inline u8 tp_info_pid_values_match(const tp_info_pid_t *left,
                                                   const tp_info_pid_t *right) {
    return left && right && bpf_memcmp(left, right, sizeof(*left)) == 0;
}

static __always_inline u8 obi_ctx_values_match(const obi_ctx_info_t *left,
                                               const obi_ctx_info_t *right) {
    return left && right && bpf_memcmp(left, right, sizeof(*left)) == 0;
}

static __noinline __attribute__((unused)) void
rollback_client_trace_publications(const connection_info_t *conn,
                                   const tp_info_pid_t *published,
                                   const client_trace_publication_target_t *target,
                                   const client_trace_publication_transaction_t *transaction) {
    if (!target || !transaction) {
        return;
    }

    const u8 publish_owner = !target->ssl && !target->vt_keyed;

    if (publish_owner && transaction->flags_updated) {
        u8 *current = bpf_map_lookup_elem(&traces_ctx_flags, &target->owner_pid_tgid);
        if (current && *current == published->tp.flags) {
            if (transaction->flags_present) {
                bpf_map_update_elem(&traces_ctx_flags,
                                    &target->owner_pid_tgid,
                                    &transaction->previous_flags,
                                    BPF_ANY);
            } else {
                bpf_map_delete_elem(&traces_ctx_flags, &target->owner_pid_tgid);
            }
        }
    }

    if (publish_owner && transaction->obi_updated) {
        obi_ctx_info_t *current = bpf_map_lookup_elem(&traces_ctx_v1, &target->owner_pid_tgid);
        if (obi_ctx_values_match(current, &transaction->published_obi)) {
            if (transaction->obi_present) {
                bpf_map_update_elem(
                    &traces_ctx_v1, &target->owner_pid_tgid, &transaction->previous_obi, BPF_ANY);
            } else {
                bpf_map_delete_elem(&traces_ctx_v1, &target->owner_pid_tgid);
            }
        }
    }

    trace_map_key_t trace_key = {};
    trace_key_from_conn(&trace_key, conn, TRACE_TYPE_CLIENT);
    if (transaction->trace_updated) {
        tp_info_pid_t *current = bpf_map_lookup_elem(&trace_map, &trace_key);
        if (tp_info_pid_values_match(current, published)) {
            if (transaction->trace_present) {
                bpf_map_update_elem(&trace_map, &trace_key, &transaction->previous_trace, BPF_ANY);
            } else {
                bpf_map_delete_elem(&trace_map, &trace_key);
            }
        }
    }

    const egress_key_t egress = make_egress_key(conn, target->host_pid, target->stream_id);
    if (transaction->outgoing_updated) {
        tp_info_pid_t *current = bpf_map_lookup_elem(&outgoing_trace_map, &egress);
        if (tp_info_pid_values_match(current, &transaction->published_outgoing)) {
            if (transaction->outgoing_present) {
                bpf_map_update_elem(
                    &outgoing_trace_map, &egress, &transaction->previous_outgoing, BPF_ANY);
            } else {
                bpf_map_delete_elem(&outgoing_trace_map, &egress);
            }
        }
    }
}

static __noinline __attribute__((unused)) long
begin_client_trace_publications(const connection_info_t *conn,
                                const tp_info_pid_t *published,
                                const client_trace_publication_target_t *target,
                                client_trace_publication_transaction_t *transaction) {
    if (!conn || !published || !target || !transaction) {
        return -1;
    }
    __builtin_memset(transaction, 0, sizeof(*transaction));

    if (!target->connection_claim_preheld) {
        const egress_key_t connection_claim = make_egress_key(conn, target->host_pid, 0);
        if (!claim_outgoing_trace_handoff_egress(&connection_claim)) {
            return -1;
        }
        transaction->connection_claim_acquired = 1;
    }

    const egress_key_t egress = make_egress_key(conn, target->host_pid, target->stream_id);
    trace_map_key_t trace_key = {};
    trace_key_from_conn(&trace_key, conn, TRACE_TYPE_CLIENT);

    tp_info_pid_t *existing_outgoing = bpf_map_lookup_elem(&outgoing_trace_map, &egress);
    if (existing_outgoing) {
        transaction->previous_outgoing = *existing_outgoing;
        transaction->outgoing_present = 1;
    }
    tp_info_pid_t *existing_trace = bpf_map_lookup_elem(&trace_map, &trace_key);
    if (existing_trace) {
        transaction->previous_trace = *existing_trace;
        transaction->trace_present = 1;
    }

    const u8 publish_owner = !target->ssl && !target->vt_keyed;
    if (publish_owner) {
        obi_ctx_info_t *existing_obi = bpf_map_lookup_elem(&traces_ctx_v1, &target->owner_pid_tgid);
        if (existing_obi) {
            transaction->previous_obi = *existing_obi;
            transaction->obi_present = 1;
        }
        u8 *existing_flags = bpf_map_lookup_elem(&traces_ctx_flags, &target->owner_pid_tgid);
        if (existing_flags) {
            transaction->previous_flags = *existing_flags;
            transaction->flags_present = 1;
        }
    }

    client_trace_publication_values(published,
                                    target->host_pid,
                                    target->ssl,
                                    &transaction->published_outgoing,
                                    &transaction->published_obi);

    const u64 outgoing_flags = target->outgoing_noexist ? BPF_NOEXIST : BPF_ANY;
    if (bpf_map_update_elem(
            &outgoing_trace_map, &egress, &transaction->published_outgoing, outgoing_flags) != 0) {
        return -1;
    }
    transaction->outgoing_updated = 1;

    if (bpf_map_update_elem(&trace_map, &trace_key, published, BPF_ANY) != 0) {
        goto failed;
    }
    transaction->trace_updated = 1;

    if (publish_owner) {
        if (bpf_map_update_elem(
                &traces_ctx_v1, &target->owner_pid_tgid, &transaction->published_obi, BPF_ANY) !=
            0) {
            goto failed;
        }
        transaction->obi_updated = 1;
        if (bpf_map_update_elem(
                &traces_ctx_flags, &target->owner_pid_tgid, &published->tp.flags, BPF_ANY) != 0) {
            goto failed;
        }
        transaction->flags_updated = 1;
    }
    return 0;

failed:
    return -1;
}

static __always_inline void
finish_client_trace_publications(const connection_info_t *conn,
                                 const client_trace_publication_target_t *target,
                                 client_trace_publication_transaction_t *transaction) {
    if (!conn || !target || !transaction || !transaction->connection_claim_acquired) {
        return;
    }
    const egress_key_t connection_claim = make_egress_key(conn, target->host_pid, 0);
    release_outgoing_trace_handoff_egress(&connection_claim);
    transaction->connection_claim_acquired = 0;
}

static __always_inline void
delete_client_trace_publications_if_matches(const connection_info_t *conn,
                                            const tp_info_pid_t *expected,
                                            u32 host_pid,
                                            u32 stream_id,
                                            u8 ssl,
                                            u64 owner_pid_tgid,
                                            u8 vt_keyed) {
    if (!conn || !expected) {
        return;
    }

    const egress_key_t egress = make_egress_key(conn, host_pid, stream_id);
    tp_info_pid_t outgoing = {};
    obi_ctx_info_t obi_info = {};
    client_trace_publication_values(expected, host_pid, ssl, &outgoing, &obi_info);

    tp_info_pid_t *current_outgoing = bpf_map_lookup_elem(&outgoing_trace_map, &egress);
    if (outgoing_trace_identity_matches(current_outgoing, &outgoing)) {
        bpf_map_delete_elem(&outgoing_trace_map, &egress);
    }

    trace_map_key_t trace_key = {};
    trace_key_from_conn(&trace_key, conn, TRACE_TYPE_CLIENT);
    tp_info_pid_t *current_trace = bpf_map_lookup_elem(&trace_map, &trace_key);
    if (outgoing_trace_identity_matches(current_trace, expected)) {
        bpf_map_delete_elem(&trace_map, &trace_key);
    }

    if (!ssl && !vt_keyed) {
        obi_ctx_info_t *current_obi = bpf_map_lookup_elem(&traces_ctx_v1, &owner_pid_tgid);
        u8 *current_flags = bpf_map_lookup_elem(&traces_ctx_flags, &owner_pid_tgid);
        if (obi_ctx_values_match(current_obi, &obi_info) && current_flags &&
            *current_flags == expected->tp.flags) {
            obi_ctx__del(owner_pid_tgid);
        }
    }
}

static __always_inline long refresh_client_trace_publications(const connection_info_t *conn,
                                                              const tp_info_pid_t *tp_p,
                                                              u32 host_pid,
                                                              u32 stream_id,
                                                              u8 ssl,
                                                              u64 owner_pid_tgid,
                                                              u8 vt_keyed) {
    const egress_key_t e_key = make_egress_key(conn, host_pid, stream_id);
    tp_info_pid_t outgoing = *tp_p;
    outgoing.pid = host_pid;
    if (ssl) {
        outgoing.valid = 0;
    }

    if (bpf_map_update_elem(&outgoing_trace_map, &e_key, &outgoing, BPF_ANY) != 0 ||
        try_set_trace_info_for_connection(conn, TRACE_TYPE_CLIENT, tp_p) != 0) {
        return -1;
    }
    if (!ssl && !vt_keyed && obi_ctx__set(owner_pid_tgid, &tp_p->tp) != 0) {
        return -1;
    }
    return 0;
}

static __always_inline void server_or_client_trace(const u8 type,
                                                   connection_info_t *conn,
                                                   lw_thread_t lw_thread,
                                                   tp_info_pid_t *tp_p,
                                                   u8 ssl,
                                                   const u16 orig_dport,
                                                   u32 stream_id,
                                                   u64 map_update_flags) {
    const u64 id = bpf_get_current_pid_tgid();
    const u32 host_pid = pid_from_pid_tgid(id);

    if (type == EVENT_HTTP_REQUEST) {
        tp_p->response_sent = 0;

        trace_key_t t_key = {0};
        task_tid(&t_key.p_key);
        // Key the server trace by the mounted virtual thread's logical id,
        // if any: concurrent requests whose VTs read on the same carrier tid
        // would otherwise collide in the conflict branch below.
        const u8 vt_keyed = java_vt_translate_tid(&t_key.p_key);
        t_key.extra_id = extra_runtime_id();

        connection_info_part_t conn_part = {};
        populate_ephemeral_info(&conn_part, conn, orig_dport, host_pid, FD_SERVER);

        bpf_dbg_printk("Saving connection server span for pid=%d, tid=%d, ephemeral_port=%d",
                       t_key.p_key.pid,
                       t_key.p_key.tid,
                       conn_part.port);

        bpf_map_update_elem(&server_traces_aux, &conn_part, tp_p, BPF_ANY);

        tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);
        if (existing && existing->req_type == tp_p->req_type &&
            tp_p->req_type == EVENT_HTTP_REQUEST && existing->valid && !existing->response_sent) {
            existing->valid = 0;
            bpf_dbg_printk("Found conflicting thread server span, marking it invalid.");
            return;
        }

        bpf_dbg_printk(
            "Saving thread server span for ns=%x, extra_id=%llx", t_key.p_key.ns, t_key.extra_id);
        bpf_map_update_elem(&server_traces, &t_key, tp_p, BPF_ANY);
        // traces_ctx_v1 stays keyed by the raw pid_tgid (external surface):
        // skip it for VT-handled requests, where a carrier-keyed entry would
        // attribute this context to whatever runs on the carrier next.
        if (!vt_keyed) {
            obi_ctx__set(id, &tp_p->tp);
        }

        // If we have lightweight passed on (e.g. goroutine), store the traceparent information on it
        if (lw_thread != k_lw_thread_none) {
            bpf_d_printk("saving tp for lightweight thread=%llx", lw_thread);

            go_addr_key_t g_key = {};
            go_addr_key_from_id_and_pid(&g_key, (void *)lw_thread, host_pid);

            push_go_trace(&g_key, &tp_p->tp);
        }
    } else {
        // Setup a pid, so that we can find it in TC.
        // We need the PID id to be able to query ongoing_http and update
        // the span id with the SEQ/ACK pair.
        tp_p->pid = host_pid;
        const egress_key_t e_key = make_egress_key(conn, host_pid, stream_id);

        if (ssl) {
            // Clone and mark it invalid for the purpose of storing it in the
            // outgoing_trace_map, if it's an SSL connection
            tp_info_pid_t tp_p_invalid = {0};
            __builtin_memcpy(&tp_p_invalid, tp_p, sizeof(tp_p_invalid));
            tp_p_invalid.valid = 0;
            bpf_map_update_elem(&outgoing_trace_map, &e_key, &tp_p_invalid, map_update_flags);
        } else {
            bpf_map_update_elem(&outgoing_trace_map, &e_key, tp_p, map_update_flags);
            if (!java_vt_mounted()) {
                obi_ctx__set(id, &tp_p->tp);
            }
        }
    }
}
