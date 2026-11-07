// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/event_defs.h>
#include <common/http_trace_parent.h>
#include <common/lw_thread.h>
#include <common/python_task.h>
#include <common/runtime.h>
#include <common/trace_helpers.h>

#include <pid/pid_helpers.h>

#include <gotracer/go_common.h>

#include <maps/clone_map.h>
#include <maps/cp_support_connect_info.h>
#include <maps/fd_map.h>
#include <maps/fd_to_connection.h>
#include <maps/java_tasks.h>
#include <maps/java_vt_threads.h>
#include <maps/nginx_upstream.h>
#include <maps/node_manual_ctx_shadow.h>
#include <maps/nodejs_fd_map.h>
#include <maps/puma_tasks.h>
#include <maps/python_thread_state.h>
#include <maps/server_traces.h>
#include <maps/tp_info_mem.h>

static __always_inline enum parent_status parent_kind(const tp_info_pid_t *server_tp) {
    if (server_tp->req_type == k_event_type_tcp_request) {
        return k_parent_status_conditional;
    }

    // under high request volume the server span is submitted at the first
    // response send, so the end timestamp a child would be settled against is
    // not the request's real end: the link cannot be judged and must stand
    if (server_tp->response_sent && !high_request_volume) {
        return k_parent_status_conditional;
    }

    return k_parent_status_live;
}

// Wire information is an explicit constraint of what should be the trace parent
static __always_inline bool parent_trace_matches(const tp_info_pid_t *parent_tp,
                                                 const tp_info_t *wire_tp) {
    if (!parent_tp) {
        return false;
    }

    if (!wire_tp) {
        // Callers validate parents selected without propagated context.
        return true;
    }

    if (!parent_tp->valid) {
        return false;
    }

    if (bpf_memcmp(parent_tp->tp.trace_id, wire_tp->trace_id, TRACE_ID_SIZE_BYTES) != 0) {
        return false;
    }

    return should_be_in_same_transaction(&parent_tp->tp, wire_tp);
}

static __always_inline tp_info_pid_t *find_wire_server_parent(u32 pid, const tp_info_t *wire_tp) {
    tp_info_pid_t *parent = find_http_server_trace(pid, wire_tp);

    return parent_trace_matches(parent, wire_tp) ? parent : NULL;
}

static __always_inline void trace_key_from_pid_tid(trace_key_t *t_key) {
    task_tid(&t_key->p_key);
    java_vt_translate_tid(&t_key->p_key);

    t_key->extra_id = extra_runtime_id();
}

static __always_inline void
trace_key_from_pid_tid_with_p_key(trace_key_t *t_key, const pid_key_t *p_key, u64 id) {
    t_key->p_key = *p_key;

    const u64 extra_id = extra_runtime_id_with_task_id(id);
    t_key->extra_id = extra_id;
}

static __always_inline tp_info_pid_t *find_nginx_parent_trace(const pid_connection_info_t *p_conn,
                                                              u16 orig_dport) {
    connection_info_part_t client_part = {};
    populate_ephemeral_info(&client_part, &p_conn->conn, orig_dport, p_conn->pid, FD_CLIENT);
    fd_info_t *fd_info = fd_info_for_conn(&client_part);

    bpf_dbg_printk("fd_info lookup=%llx, type=%d", fd_info, client_part.type);
    if (fd_info) {
        connection_info_part_t *parent = bpf_map_lookup_elem(&nginx_upstream, fd_info);
        bpf_dbg_printk("parent=%llx, fd=%d, type=%d", parent, fd_info->fd, fd_info->type);
        if (parent) {
            return bpf_map_lookup_elem(&server_traces_aux, parent);
        }
    }

    return NULL;
}

static __always_inline tp_info_pid_t *find_puma_parent_trace(u64 id) {
    puma_task_id_t *task_id = bpf_map_lookup_elem(&puma_worker_tasks, &id);
    bpf_dbg_printk("puma lookup: task_id=%llx", task_id);
    if (!task_id) {
        return NULL;
    }

    bpf_dbg_printk("found item:%llx", task_id->item);

    connection_info_part_t *conn_part = bpf_map_lookup_elem(&puma_task_connections, task_id);
    if (conn_part) {
        return bpf_map_lookup_elem(&server_traces_aux, conn_part);
    }

    return NULL;
}

static __always_inline tp_info_pid_t *
find_nodejs_parent_trace(const pid_connection_info_t *p_conn, u16 orig_dport, u64 pid_tgid) {
    connection_info_part_t client_part = {};
    populate_ephemeral_info(&client_part, &p_conn->conn, orig_dport, p_conn->pid, FD_CLIENT);
    fd_info_t *fd_info = fd_info_for_conn(&client_part);

    if (!fd_info) {
        return NULL;
    }

    const u64 client_key = (pid_tgid << 32) | fd_info->fd;

    const s32 *node_parent_request_fd = bpf_map_lookup_elem(&nodejs_fd_map, &client_key);

    if (!node_parent_request_fd) {
        return NULL;
    }

    bpf_dbg_printk("client_fd=%d, server_fd=%d", fd_info->fd, *node_parent_request_fd);

    const fd_key key = {.pid_tgid = pid_tgid, .fd = *node_parent_request_fd};

    const connection_info_t *conn = bpf_map_lookup_elem(&fd_to_connection, &key);

    if (!conn) {
        return NULL;
    }

    return trace_info_for_connection(conn, TRACE_TYPE_SERVER);
}

static __always_inline tp_info_pid_t *find_parent_process_trace(trace_key_t *t_key,
                                                                const tp_info_t *wire_tp) {
    // Up to 5 levels of thread nesting allowed
    enum { k_max_depth = 5 };

    for (u8 i = 0; i < k_max_depth; ++i) {
        tp_info_pid_t *server_tp = bpf_map_lookup_elem(&server_traces, t_key);

        if (parent_trace_matches(server_tp, wire_tp)) {
            bpf_dbg_printk("Found parent trace for pid=%d, ns=%lx, extra_id=%llx",
                           t_key->p_key.pid,
                           t_key->p_key.ns,
                           t_key->extra_id);
            return server_tp;
        }

        // not this goroutine running the server request processing
        // Let's find the parent scope
        const pid_key_t *p_tid = (const pid_key_t *)bpf_map_lookup_elem(&clone_map, &t_key->p_key);

        if (!p_tid) {
            break;
        }

        // Lookup now to see if the parent was a request
        t_key->p_key = *p_tid;
    }

    return NULL;
}

static __always_inline python_task_resolution_t
resolve_python_current_task(const trace_key_t *t_key, u64 pid_tgid, python_task_ref_t *task_ref) {
    const python_thread_state_t *thread_state =
        (const python_thread_state_t *)bpf_map_lookup_elem(&python_thread_state, &pid_tgid);

    if (!thread_state) {
        return PYTHON_TASK_NOT_FOUND;
    }

    if (thread_state->current_task) {
        if (resolve_python_task_ref(pid_tgid, thread_state->current_task, task_ref)) {
            bpf_dbg_printk("resolve_python_current_task: resolved tid=%d task=%llx",
                           t_key->p_key.tid,
                           thread_state->current_task);
            return PYTHON_TASK_RESOLVED;
        }
        return PYTHON_TASK_STALE;
    }

    if (!thread_state->current_context) {
        return PYTHON_TASK_NOT_FOUND;
    }

    // asyncio.to_thread can switch work onto a thread that inherited a context
    // but has not run task_step, so the current context is the only usable link.
    const python_task_resolution_t resolution =
        resolve_python_task_from_context(pid_tgid, thread_state->current_context, task_ref);
    if (resolution == PYTHON_TASK_RESOLVED) {
        bpf_dbg_printk("resolve_python_current_task: context fallback tid=%d ctx=%llx task=%llx",
                       t_key->p_key.tid,
                       thread_state->current_context,
                       task_ref->addr);
    }
    return resolution;
}

static __always_inline tp_info_pid_t *
find_python_parent_trace(const trace_key_t *t_key, u64 pid_tgid, u8 *allow_parent_fallback) {
    if (allow_parent_fallback) {
        *allow_parent_fallback = 1;
    }

    python_task_ref_t task_ref = {};
    const python_task_resolution_t task_resolution =
        resolve_python_current_task(t_key, pid_tgid, &task_ref);
    if (task_resolution != PYTHON_TASK_RESOLVED) {
        if (task_resolution == PYTHON_TASK_STALE && allow_parent_fallback) {
            *allow_parent_fallback = 0;
        }
        bpf_dbg_printk(
            "python parent unresolved tid=%d status=%d", t_key->p_key.tid, task_resolution);
        return NULL;
    }

    python_task_resolution_t owning_resolution = PYTHON_TASK_NOT_FOUND;
    tp_info_pid_t *server_tp =
        find_python_owning_server_trace(pid_tgid, task_ref, &owning_resolution);
    if (owning_resolution == PYTHON_TASK_STALE && allow_parent_fallback) {
        *allow_parent_fallback = 0;
    }
    if (server_tp) {
        bpf_dbg_printk(
            "find_python_parent_trace: FOUND tid=%d task=%llx", t_key->p_key.tid, task_ref.addr);
    } else {
        bpf_dbg_printk("find_python_parent_trace: no owning trace for tid=%d task=%llx",
                       t_key->p_key.tid,
                       task_ref.addr);
    }
    return server_tp;
}

static __always_inline tp_info_pid_t *find_parent_java_trace(trace_key_t *t_key,
                                                             const tp_info_t *wire_tp) {
    // Up to 3 levels of thread nesting allowed
    enum { k_max_depth = 3 };

    for (u8 i = 0; i < k_max_depth; ++i) {
        tp_info_pid_t *server_tp = bpf_map_lookup_elem(&server_traces, t_key);

        if (parent_trace_matches(server_tp, wire_tp)) {
            bpf_dbg_printk("Found parent trace for pid=%d, ns=%lx, extra_id=%llx",
                           t_key->p_key.pid,
                           t_key->p_key.ns,
                           t_key->extra_id);
            return server_tp;
        }

        // not this java thread running the server request processing
        // Let's find the parent scope
        const pid_key_t *p_tid = (const pid_key_t *)bpf_map_lookup_elem(&java_tasks, &t_key->p_key);

        if (!p_tid) {
            break;
        }

        // Lookup now to see if the parent was a request
        t_key->p_key = *p_tid;
    }

    return NULL;
}

// Helper to clean-up Go trace information when we use Go generic support, e.g. the Go fiber framework.
static __always_inline void delete_go_trace_info(const lw_thread_t lw_thread, const u32 pid) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id_and_pid(&g_key, (void *)lw_thread, pid);

    bpf_map_delete_elem(&go_trace_map, &g_key);
}

// Only used for Go generic support, e.g Go fiber, when we handle the requests using the
// generic protocol parsers.
static __always_inline tp_info_pid_t *find_go_parent_trace(const lw_thread_t lw_thread,
                                                           const u32 pid) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id_and_pid(&g_key, (void *)lw_thread, pid);

    u64 parent_id = find_parent_goroutine(&g_key);
    if (parent_id) {
        go_addr_key_t p_key = {};
        go_addr_key_from_id_and_pid(&p_key, (void *)parent_id, pid);

        tp_info_t *p_inv = bpf_map_lookup_elem(&go_trace_map, &p_key);
        if (p_inv) {
            // Using backup scratch memory to avoid upstream users of the
            // trace parent info to use tp_info_mem and get the same pointer.
            // Typically this is not a problem because for other languages we
            // pull map info, but Go tracer doesn't store the full tp_info_pid_t,
            // only the pidless tp_info_t.
            tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_backup_mem();
            if (!tp_p) {
                return NULL;
            }

            tp_p->tp = *p_inv;
            tp_p->valid = 1;
            tp_p->written = 0;
            tp_p->pid = pid;
            // if we found it in the go_trace_map, it's always a server request
            tp_p->req_type = k_event_type_http_request;

            return tp_p;
        }
    }

    return NULL;
}

static __always_inline tp_info_pid_t *find_parent_trace(const pid_connection_info_t *p_conn,
                                                        u64 pid_tgid,
                                                        lw_thread_t lw_thread,
                                                        trace_key_t *t_key,
                                                        u16 orig_dport,
                                                        const tp_info_t *wire_tp) {
    tp_info_pid_t *node_tp = find_nodejs_parent_trace(p_conn, orig_dport, pid_tgid);

    if (parent_trace_matches(node_tp, wire_tp)) {
        return node_tp;
    }

    bpf_dbg_printk("Looking up parent trace for pid=%d, ns=%lx, extra_id=%llx",
                   t_key->p_key.pid,
                   t_key->p_key.ns,
                   t_key->extra_id);

    if (lw_thread != k_lw_thread_none) {
        const u32 host_pid = pid_from_pid_tgid(pid_tgid);
        bpf_dbg_printk("Looking up parent trace for pid=%d, lw_thread=%llx", host_pid, lw_thread);
        tp_info_pid_t *go_parent = find_go_parent_trace(lw_thread, host_pid);
        if (parent_trace_matches(go_parent, wire_tp)) {
            return go_parent;
        }
    }

    u8 allow_parent_fallback = 1;
    tp_info_pid_t *python_parent =
        find_python_parent_trace(t_key, pid_tgid, &allow_parent_fallback);

    if (!allow_parent_fallback) {
        return parent_trace_matches(python_parent, wire_tp) ? python_parent : NULL;
    }

    if (parent_trace_matches(python_parent, wire_tp)) {
        return python_parent;
    }

    tp_info_pid_t *nginx_parent = find_nginx_parent_trace(p_conn, orig_dport);

    if (parent_trace_matches(nginx_parent, wire_tp)) {
        return nginx_parent;
    }

    tp_info_pid_t *puma_parent = find_puma_parent_trace(pid_tgid);
    if (parent_trace_matches(puma_parent, wire_tp)) {
        return puma_parent;
    }

    // Virtual threads and submitted Java tasks identify their logical request, so
    // only other threads prefer the server request indexed under the wire trace.
    const bool index_first = wire_tp && !(t_key->p_key.tid & JAVA_VT_TID_FLAG) &&
                             !bpf_map_lookup_elem(&java_tasks, &t_key->p_key);

    if (index_first) {
        tp_info_pid_t *http_parent = find_wire_server_parent(p_conn->pid, wire_tp);
        if (http_parent) {
            return http_parent;
        }
    }

    tp_info_pid_t *java_parent = find_parent_java_trace(t_key, wire_tp);
    if (java_parent) {
        return java_parent;
    }

    if (wire_tp && !index_first) {
        tp_info_pid_t *http_parent = find_wire_server_parent(p_conn->pid, wire_tp);
        if (http_parent) {
            return http_parent;
        }
    }

    tp_info_pid_t *proc_parent = find_parent_process_trace(t_key, wire_tp);

    if (proc_parent) {
        return proc_parent;
    }

    const cp_support_data_t *conn_t_key = bpf_map_lookup_elem(&cp_support_connect_info, p_conn);

    if (conn_t_key) {
        bpf_dbg_printk("Found parent trace for connection through connection lookup");
        tp_info_pid_t *parent = bpf_map_lookup_elem(&server_traces, &conn_t_key->t_key);
        if (parent_trace_matches(parent, wire_tp)) {
            return parent;
        }
    }

    return 0;
}

static __always_inline u8 nodejs_manual_parent_span_id(u64 pid_tgid,
                                                       const unsigned char *trace_id,
                                                       unsigned char *span_id_out) {
    // no shadow: this thread is not inside a Node.js manual span
    const obi_ctx_info_t *shadow = bpf_map_lookup_elem(&node_manual_ctx_shadow, &pid_tgid);
    if (!shadow) {
        return 0;
    }
    const obi_ctx_info_t *live = bpf_map_lookup_elem(&traces_ctx_v1, &pid_tgid);
    if (!live) {
        return 0;
    }
    if (bpf_memcmp(live->trace_id, trace_id, TRACE_ID_SIZE_BYTES) != 0) {
        return 0;
    }
    __builtin_memcpy(span_id_out, live->span_id, SPAN_ID_SIZE_BYTES);
    return 1;
}

static __always_inline u8
find_trace_for_client_request_with_t_key(const pid_connection_info_t *p_conn,
                                         u16 orig_dport,
                                         trace_key_t *t_key,
                                         u64 pid_tgid,
                                         lw_thread_t lw_thread,
                                         tp_info_t *tp) {
    tp_info_pid_t *server_tp =
        find_parent_trace(p_conn, pid_tgid, lw_thread, t_key, orig_dport, NULL);

    if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
        bpf_dbg_printk("Found existing server tp for client call");

        if (!should_be_in_same_transaction(&server_tp->tp, tp)) {
            bpf_dbg_printk("Parent and child are too far apart, discarding the parent trace");
            bpf_dbg_printk(
                "%lld >>> %lld (max: %lld)", tp->ts, server_tp->tp.ts, max_transaction_time);
            if (parent_trace_is_stale(&server_tp->tp, tp)) {
                server_tp->valid = 0;
            }
            return 0;
        }

        __builtin_memcpy(tp->trace_id, server_tp->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, server_tp->tp.span_id, sizeof(tp->parent_id));
        tp->flags = server_tp->tp.flags;

        if (nodejs_manual_parent_span_id(pid_tgid, tp->trace_id, tp->parent_id)) {
            return k_parent_status_live;
        }
        return parent_kind(server_tp);
    }

    return k_parent_status_none;
}

static __always_inline u8 find_trace_for_client_request(const pid_connection_info_t *p_conn,
                                                        u16 orig_dport,
                                                        lw_thread_t lw_thread,
                                                        tp_info_t *tp) {

    trace_key_t t_key = {0};
    trace_key_from_pid_tid(&t_key);
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    return find_trace_for_client_request_with_t_key(
        p_conn, orig_dport, &t_key, pid_tgid, lw_thread, tp);
}

static __always_inline u8
find_parent_trace_for_client_request_with_t_key(const pid_connection_info_t *p_conn,
                                                u16 orig_dport,
                                                trace_key_t *t_key,
                                                u64 pid_tgid,
                                                lw_thread_t lw_thread,
                                                tp_info_t *tp,
                                                const tp_info_t *wire_tp) {
    tp_info_pid_t *server_tp =
        find_parent_trace(p_conn, pid_tgid, lw_thread, t_key, orig_dport, wire_tp);

    if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
        bpf_dbg_printk("Found existing server tp for client call");

        if (!should_be_in_same_transaction(&server_tp->tp, tp)) {
            bpf_dbg_printk("Parent and child are too far apart, discarding the parent trace");
            bpf_dbg_printk(
                "%lld >>> %lld (max: %lld)", tp->ts, server_tp->tp.ts, max_transaction_time);
            if (parent_trace_is_stale(&server_tp->tp, tp)) {
                server_tp->valid = 0;
            }
            return 0;
        }

        *tp = server_tp->tp;

        if (nodejs_manual_parent_span_id(pid_tgid, tp->trace_id, tp->span_id)) {
            return k_parent_status_live;
        }
        return parent_kind(server_tp);
    }

    return 0;
}

static __always_inline u8 find_parent_trace_for_client_request(const pid_connection_info_t *p_conn,
                                                               u16 orig_dport,
                                                               lw_thread_t lw_thread,
                                                               tp_info_t *tp,
                                                               const tp_info_t *wire_tp) {

    trace_key_t t_key = {0};
    trace_key_from_pid_tid(&t_key);
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    return find_parent_trace_for_client_request_with_t_key(
        p_conn, orig_dport, &t_key, pid_tgid, lw_thread, tp, wire_tp);
}

// Adopt only the parent: the library already chose the client's identity and flags,
// unless it forwarded the inbound header unchanged.
static __always_inline u8 find_trace_for_wire_client_request(const pid_connection_info_t *p_conn,
                                                             u16 orig_dport,
                                                             lw_thread_t lw_thread,
                                                             tp_info_t *wire_tp) {
    if (!wire_tp) {
        return k_parent_status_none;
    }

    __builtin_memset(wire_tp->parent_id, 0, sizeof(wire_tp->parent_id));
    if (!valid_trace(wire_tp->trace_id) || !valid_span(wire_tp->span_id)) {
        return k_parent_status_none;
    }

    trace_key_t key = {};
    trace_key_from_pid_tid(&key);
    const u64 id = bpf_get_current_pid_tgid();
    tp_info_pid_t *parent = find_parent_trace(p_conn, id, lw_thread, &key, orig_dport, wire_tp);

    if (!parent) {
        return k_parent_status_none;
    }

    // The header can't be rewritten from a kprobe, so only the client span gets a
    // new ID. Reusing the caller's would duplicate it and loop back to the parent.
    // This essentially handles forwarding proxies.
    if (bpf_memcmp(wire_tp->span_id, parent->tp.parent_id, SPAN_ID_SIZE_BYTES) == 0) {
        urand_bytes(wire_tp->span_id, SPAN_ID_SIZE_BYTES);
    }

    __builtin_memcpy(wire_tp->parent_id, parent->tp.span_id, sizeof(wire_tp->parent_id));
    if (nodejs_manual_parent_span_id(id, wire_tp->trace_id, wire_tp->parent_id)) {
        return k_parent_status_live;
    }

    return parent_kind(parent);
}
