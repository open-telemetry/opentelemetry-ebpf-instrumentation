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

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/http_types.h>
#include <common/lw_thread.h>

#include <gotracer/go_common.h>
#include <gotracer/maps/mongo.h>
#include <gotracer/maps/ongoing_fd_reads.h>

#include <generictracer/k_tracer_defs.h>

#include <logger/bpf_dbg.h>

#include <maps/outgoing_trace_map.h>
#include <maps/ongoing_tcp_req.h>
#include <maps/ongoing_http2_connections.h>

#include <gotracer/types/net_args.h>

#include <pid/pid_helpers.h>

#include <shared/obi_ctx.h>

static __always_inline bool already_handled_request_sorted(const connection_info_t *conn) {
    if (conn) {
        const bool *found = bpf_map_lookup_elem(&handled_by_go_conn, conn);
        if (found) {
            return true;
        }
    }
    return false;
}

static __always_inline void
cleanup_duplicate_generic_events_sorted(const pid_connection_info_t *pid_conn) {
    if (!pid_conn) {
        return;
    }
    bpf_map_delete_elem(&ongoing_http, pid_conn);
    bpf_map_delete_elem(&ongoing_tcp_req, pid_conn);
    bpf_map_delete_elem(&ongoing_http2_connections, pid_conn);
}

static __always_inline void
cleanup_duplicate_generic_event_by_connection(const connection_info_t *conn) {
    if (!conn) {
        return;
    }
    const u64 id = bpf_get_current_pid_tgid();
    pid_connection_info_t p_conn = {.conn = *conn, .pid = pid_from_pid_tgid(id)};
    sort_connection_info(&p_conn.conn);

    cleanup_duplicate_generic_events_sorted(&p_conn);
}

SEC("uprobe/netFdRead")
int obi_uprobe_netFdRead(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk(
        "=== uprobe/netFdRead goroutine_addr=%lx, fd=%llx === ", goroutine_addr, GO_PARAM1(ctx));

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    // lookup a grpc connection
    // Sets up the connection info to be grabbed and mapped over the transport to operateHeaders
    void *tr = bpf_map_lookup_elem(&ongoing_grpc_operate_headers, &g_key);
    bpf_dbg_printk("tr=%llx", tr);
    if (tr) {
        grpc_transports_t *t = bpf_map_lookup_elem(&ongoing_grpc_transports, tr);
        bpf_dbg_printk("t=%llx", t);
        if (t) {
            if (t->conn.d_port == 0 && t->conn.s_port == 0) {
                void *fd_ptr = GO_PARAM1(ctx);
                get_conn_info_from_fd(fd_ptr,
                                      &t->conn,
                                      true); // ok to not check the result, we leave it as 0
                cleanup_duplicate_generic_event_by_connection(&t->conn);
            }
        }
        return 0;
    }

    // lookup active sql connection
    sql_func_invocation_t *sql_conn = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
    bpf_dbg_printk("sql_conn=%llx", sql_conn);
    if (sql_conn) {
        void *fd_ptr = GO_PARAM1(ctx);
        get_conn_info_from_fd(fd_ptr,
                              &sql_conn->conn,
                              true); // ok to not check the result, we leave it as 0
        cleanup_duplicate_generic_event_by_connection(&sql_conn->conn);
        return 0;
    }

    mongo_go_client_req_t *mongo_conn = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    bpf_dbg_printk("mongo_conn=%llx", mongo_conn);
    if (mongo_conn) {
        void *fd_ptr = GO_PARAM1(ctx);
        get_conn_info_from_fd(fd_ptr,
                              &mongo_conn->conn,
                              true); // ok to not check the result, we leave it as 0

        cleanup_duplicate_generic_event_by_connection(&mongo_conn->conn);
        return 0;
    }

    // lookup active HTTP connection
    connection_info_t *conn = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
    bpf_dbg_printk("conn=%llx", conn);
    if (conn) {
        if (conn->d_port == 0 && conn->s_port == 0) {
            bpf_dbg_printk("Found existing server connection, parsing FD information for socket "
                           "tuples, goroutine_addr=%llx",
                           goroutine_addr);

            void *fd_ptr = GO_PARAM1(ctx);
            get_conn_info_from_fd(
                fd_ptr, conn, true); // ok to not check the result, we leave it as 0
            cleanup_duplicate_generic_event_by_connection(conn);

            return 0;
        }
        //dbg_print_http_connection_info(conn);
        // We cannot return here, HTTP servers are typically wrapping unknown protocols
        // on the same goroutine.
    }

    const u64 id = bpf_get_current_pid_tgid();

    void *fd_ptr = GO_PARAM1(ctx);
    void *byte_addr = GO_PARAM2(ctx);
    net_args_t net_args = {
        .byte_ptr = (u64)byte_addr,
    };

    if (!get_conn_info_from_fd(fd_ptr, &net_args.p_conn.conn, false)) {
        return 0;
    }

    net_args.p_conn.pid = pid_from_pid_tgid(id);

    dbg_print_http_connection_info(&net_args.p_conn.conn);

    pid_connection_info_t p_conn = net_args.p_conn;

    sort_connection_info(&p_conn.conn);

    if (already_handled_request_sorted(&p_conn.conn)) {
        cleanup_duplicate_generic_events_sorted(&p_conn);
        return 0;
    }

    bpf_map_update_elem(&ongoing_fd_reads, &g_key, &net_args, BPF_ANY);

    return 0;
}

SEC("uprobe/netFdReadRet")
int obi_uprobe_netFdReadRet(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc netFD read returns goroutine %lx === ", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    net_args_t *net_ptr = bpf_map_lookup_elem(&ongoing_fd_reads, &g_key);
    if (!net_ptr || !net_ptr->byte_ptr) {
        return 0;
    }

    void *buf = (void *)net_ptr->byte_ptr;

    s64 len = (s64)GO_PARAM1(ctx);
    bpf_dbg_printk("buf=%llx, len=%lld === ", (unsigned long long)buf, (long long)len);
    if (buf && len > 0) {
        const int bytes_len = (int)min((s64)__INT_MAX__, len);

        dbg_print_http_connection_info(&net_ptr->p_conn.conn);

        u16 orig_dport = net_ptr->p_conn.conn.d_port;
        sort_connection_info(&net_ptr->p_conn.conn);

        dbg_print_http_connection_info(&net_ptr->p_conn.conn);

        bpf_map_delete_elem(&ongoing_fd_reads, &g_key);
        // doesn't return
        handle_light_weight_thread_buf(ctx,
                                       (lw_thread_t)goroutine_addr,
                                       (protocol_selector_t){.http = 1, .http2 = 0, .tcp = 1},
                                       &net_ptr->p_conn,
                                       buf,
                                       bytes_len,
                                       NO_SSL,
                                       TCP_RECV,
                                       orig_dport);
    }

    bpf_map_delete_elem(&ongoing_fd_reads, &g_key);

    return 0;
}

SEC("uprobe/netFdWrite")
int obi_uprobe_netFdWrite(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc netFD write goroutine=%lx, fd_ptr=%llx === ",
                   goroutine_addr,
                   GO_PARAM1(ctx));

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *fd_ptr = GO_PARAM1(ctx);
    u8 *buf = GO_PARAM2(ctx);
    s64 len = (s64)GO_PARAM3(ctx);
    if (buf && len > 0) {
        const int bytes_len = (int)min((s64)__INT_MAX__, len);
        pid_connection_info_t p_conn = {0};

        if (!get_conn_info_from_fd(fd_ptr, &p_conn.conn, false)) {
            return 0;
        }

        p_conn.pid = pid_from_pid_tgid(id);

        u16 orig_dport = p_conn.conn.d_port;
        sort_connection_info(&p_conn.conn);

        dbg_print_http_connection_info(&p_conn.conn);

        if (already_handled_request_sorted(&p_conn.conn)) {
            cleanup_duplicate_generic_events_sorted(&p_conn);
            return 0;
        }

        // doesn't return
        handle_light_weight_thread_buf(ctx,
                                       (lw_thread_t)goroutine_addr,
                                       (protocol_selector_t){.http = 1, .http2 = 0, .tcp = 1},
                                       &p_conn,
                                       buf,
                                       bytes_len,
                                       NO_SSL,
                                       TCP_SEND,
                                       orig_dport);
    }

    return 0;
}

SEC("uprobe/netFdClose")
int obi_uprobe_netFdClose(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc netFD close goroutine %lx === ", GOROUTINE_PTR(ctx));

    void *fd_ptr = GO_PARAM1(ctx);

    if (!fd_ptr) {
        return 0;
    }

    connection_info_t conn = {0};

    if (!get_conn_info_from_fd(fd_ptr, &conn, false)) {
        return 0;
    }

    sort_connection_info(&conn);

    dbg_print_http_connection_info(&conn);

    remove_go_handled_connection(&conn);

    return 0;
}
