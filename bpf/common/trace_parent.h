// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/python_task.h>
#include <common/runtime.h>
#include <common/trace_helpers.h>

#include <maps/clone_map.h>
#include <maps/cp_support_connect_info.h>
#include <maps/fd_map.h>
#include <maps/fd_to_connection.h>
#include <maps/java_tasks.h>
#include <maps/nginx_upstream.h>
#include <maps/nodejs_fd_map.h>
#include <maps/puma_tasks.h>
#include <maps/python_thread_state.h>
#include <maps/server_traces.h>

static __always_inline void trace_key_from_pid_tid(trace_key_t *t_key) {
    task_tid(&t_key->p_key);

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

static __always_inline tp_info_pid_t *find_parent_process_trace(trace_key_t *t_key) {
    // Up to 5 levels of thread nesting allowed
    enum { k_max_depth = 5 };

    for (u8 i = 0; i < k_max_depth; ++i) {
        tp_info_pid_t *server_tp = bpf_map_lookup_elem(&server_traces, t_key);

        if (server_tp) {
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

static __always_inline u64 resolve_python_current_task(const trace_key_t *t_key, u64 pid_tgid) {
    const python_thread_state_t *thread_state =
        (const python_thread_state_t *)bpf_map_lookup_elem(&python_thread_state, &pid_tgid);

    if (!thread_state) {
        return 0;
    }

    if (thread_state->current_task) {
        bpf_dbg_printk("resolve_python_current_task: resolved tid=%d task=%llx",
                       t_key->p_key.tid,
                       thread_state->current_task);
        return thread_state->current_task;
    }

    if (!thread_state->current_context) {
        return 0;
    }

    // asyncio.to_thread can switch work onto a thread that inherited a context
    // but has not run task_step, so current_context is the only usable link.
    const python_context_task_t *context_task = (const python_context_task_t *)bpf_map_lookup_elem(
        &python_context_task, &thread_state->current_context);
    const u64 task_id = resolve_python_context_task(context_task);
    if (task_id) {
        bpf_dbg_printk("resolve_python_current_task: context fallback tid=%d ctx=%llx task=%llx",
                       t_key->p_key.tid,
                       thread_state->current_context,
                       task_id);
        return task_id;
    }
    return 0;
}

static __always_inline tp_info_pid_t *find_python_parent_trace(const trace_key_t *t_key,
                                                               u64 pid_tgid) {
    enum { k_max_depth = 4 };

    u64 task_id = resolve_python_current_task(t_key, pid_tgid);

    if (!task_id) {
        bpf_dbg_printk("find_python_parent_trace: no current task pid=%d tid=%d",
                       t_key->p_key.pid,
                       t_key->p_key.tid);
        return NULL;
    }

    for (u8 i = 0; i < k_max_depth; ++i) {
        const python_task_state_t *task_state =
            (const python_task_state_t *)bpf_map_lookup_elem(&python_task_state, &task_id);
        if (!task_state) {
            bpf_dbg_printk("find_python_parent_trace: no task state for tid=%d task=%llx",
                           t_key->p_key.tid,
                           task_id);
            break;
        }

        if (task_state->conn.port) {
            tp_info_pid_t *server_tp = bpf_map_lookup_elem(&server_traces_aux, &task_state->conn);
            if (server_tp) {
                bpf_dbg_printk("find_python_parent_trace: FOUND tid=%d task=%llx port=%d",
                               t_key->p_key.tid,
                               task_id,
                               task_state->conn.port);
                return server_tp;
            }
        }

        if (!task_state->parent) {
            bpf_dbg_printk("find_python_parent_trace: no parent for tid=%d task=%llx",
                           t_key->p_key.tid,
                           task_id);
            break;
        }

        task_id = task_state->parent;
    }

    return NULL;
}

static __always_inline tp_info_pid_t *find_parent_java_trace(trace_key_t *t_key) {
    // Up to 3 levels of thread nesting allowed
    enum { k_max_depth = 3 };

    for (u8 i = 0; i < k_max_depth; ++i) {
        tp_info_pid_t *server_tp = bpf_map_lookup_elem(&server_traces, t_key);

        if (server_tp) {
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

static __always_inline tp_info_pid_t *find_parent_trace(const pid_connection_info_t *p_conn,
                                                        u64 pid_tgid,
                                                        trace_key_t *t_key,
                                                        u16 orig_dport) {
    tp_info_pid_t *node_tp = find_nodejs_parent_trace(p_conn, orig_dport, pid_tgid);

    if (node_tp) {
        return node_tp;
    }

    bpf_dbg_printk("Looking up parent trace for pid=%d, ns=%lx, extra_id=%llx",
                   t_key->p_key.pid,
                   t_key->p_key.ns,
                   t_key->extra_id);

    tp_info_pid_t *python_parent = find_python_parent_trace(t_key, pid_tgid);
    if (python_parent) {
        return python_parent;
    }

    tp_info_pid_t *nginx_parent = find_nginx_parent_trace(p_conn, orig_dport);

    if (nginx_parent) {
        return nginx_parent;
    }

    tp_info_pid_t *puma_parent = find_puma_parent_trace(pid_tgid);
    if (puma_parent) {
        return puma_parent;
    }

    tp_info_pid_t *java_parent = find_parent_java_trace(t_key);
    if (java_parent) {
        return java_parent;
    }

    tp_info_pid_t *proc_parent = find_parent_process_trace(t_key);

    if (proc_parent) {
        return proc_parent;
    }

    const cp_support_data_t *conn_t_key = bpf_map_lookup_elem(&cp_support_connect_info, p_conn);

    if (conn_t_key) {
        bpf_dbg_printk("Found parent trace for connection through connection lookup");
        return bpf_map_lookup_elem(&server_traces, &conn_t_key->t_key);
    }

    return 0;
}

static __always_inline u8
find_trace_for_client_request_with_t_key(const pid_connection_info_t *p_conn,
                                         u16 orig_dport,
                                         trace_key_t *t_key,
                                         u64 pid_tgid,
                                         tp_info_t *tp) {
    tp_info_pid_t *server_tp = find_parent_trace(p_conn, pid_tgid, t_key, orig_dport);

    if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
        bpf_dbg_printk("Found existing server tp for client call");

        if (!should_be_in_same_transaction(&server_tp->tp, tp)) {
            bpf_dbg_printk("Parent and child are too far apart, marking server trace as invalid");
            bpf_dbg_printk(
                "%lld >>> %lld (max: %lld)", tp->ts, server_tp->tp.ts, max_transaction_time);
            server_tp->valid = 0;
            return 0;
        }

        __builtin_memcpy(tp->trace_id, server_tp->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, server_tp->tp.span_id, sizeof(tp->parent_id));
        return 1;
    }

    return 0;
}

static __always_inline u8 find_trace_for_client_request(const pid_connection_info_t *p_conn,
                                                        u16 orig_dport,
                                                        tp_info_t *tp) {

    trace_key_t t_key = {0};
    trace_key_from_pid_tid(&t_key);
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    return find_trace_for_client_request_with_t_key(p_conn, orig_dport, &t_key, pid_tgid, tp);
}

static __always_inline u8
find_parent_trace_for_client_request_with_t_key(const pid_connection_info_t *p_conn,
                                                u16 orig_dport,
                                                trace_key_t *t_key,
                                                u64 pid_tgid,
                                                tp_info_t *tp) {
    tp_info_pid_t *server_tp = find_parent_trace(p_conn, pid_tgid, t_key, orig_dport);

    if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
        bpf_dbg_printk("Found existing server tp for client call");

        if (!should_be_in_same_transaction(&server_tp->tp, tp)) {
            bpf_dbg_printk("Parent and child are too far apart, marking server trace as invalid");
            bpf_dbg_printk(
                "%lld >>> %lld (max: %lld)", tp->ts, server_tp->tp.ts, max_transaction_time);
            server_tp->valid = 0;
            return 0;
        }

        *tp = server_tp->tp;
        return 1;
    }

    return 0;
}

static __always_inline u8 find_parent_trace_for_client_request(const pid_connection_info_t *p_conn,
                                                               u16 orig_dport,
                                                               tp_info_t *tp) {

    trace_key_t t_key = {0};
    trace_key_from_pid_tid(&t_key);
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    return find_parent_trace_for_client_request_with_t_key(
        p_conn, orig_dport, &t_key, pid_tgid, tp);
}
