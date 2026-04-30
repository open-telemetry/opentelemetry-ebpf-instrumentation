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

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/algorithm.h>
#include <common/common.h>
#include <common/connection_info.h>
#include <common/go_addr_key.h>

#include <gotracer/go_common.h>
#include <gotracer/maps/mongo.h>

#include <generictracer/k_tracer_defs.h>

#include <logger/bpf_dbg.h>

#include <maps/ongoing_tcp_req.h>
#include <maps/ongoing_http2_connections.h>

#include <pid/pid_helpers.h>

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

static __always_inline bool already_handled_goroutine(go_addr_key_t *g_key, void *fd_ptr) {
    // lookup a grpc connection
    // Sets up the connection info to be grabbed and mapped over the transport to operateHeaders
    void *tr = bpf_map_lookup_elem(&ongoing_grpc_operate_headers, g_key);
    bpf_dbg_printk("tr=%llx", tr);
    if (tr) {
        grpc_transports_t *t = bpf_map_lookup_elem(&ongoing_grpc_transports, tr);
        bpf_dbg_printk("t=%llx", t);
        if (t) {
            if (t->conn.d_port == 0 && t->conn.s_port == 0) {
                get_conn_info_from_fd(fd_ptr,
                                      &t->conn,
                                      true); // ok to not check the result, we leave it as 0
                cleanup_duplicate_generic_event_by_connection(&t->conn);
            }
        }
        return true;
    }

    // lookup active sql connection
    sql_func_invocation_t *sql_conn = bpf_map_lookup_elem(&ongoing_sql_queries, g_key);
    bpf_dbg_printk("sql_conn=%llx", sql_conn);
    if (sql_conn) {
        get_conn_info_from_fd(fd_ptr,
                              &sql_conn->conn,
                              true); // ok to not check the result, we leave it as 0
        cleanup_duplicate_generic_event_by_connection(&sql_conn->conn);
        return true;
    }

    mongo_go_client_req_t *mongo_conn = bpf_map_lookup_elem(&ongoing_mongo_requests, g_key);
    bpf_dbg_printk("mongo_conn=%llx", mongo_conn);
    if (mongo_conn) {
        get_conn_info_from_fd(fd_ptr,
                              &mongo_conn->conn,
                              true); // ok to not check the result, we leave it as 0

        cleanup_duplicate_generic_event_by_connection(&mongo_conn->conn);
        return true;
    }

    // lookup active HTTP connection
    connection_info_t *conn = bpf_map_lookup_elem(&ongoing_server_connections, g_key);
    bpf_dbg_printk("conn=%llx", conn);
    if (conn) {
        if (conn->d_port == 0 && conn->s_port == 0) {
            bpf_dbg_printk("Found existing server connection, parsing FD information for socket "
                           "tuples, goroutine_addr=%llx",
                           g_key->addr);

            get_conn_info_from_fd(
                fd_ptr, conn, true); // ok to not check the result, we leave it as 0
            cleanup_duplicate_generic_event_by_connection(conn);

            return true;
        }
        //dbg_print_http_connection_info(conn);
        // We cannot return true here, HTTP servers are typically wrapping unknown protocols
        // on the same goroutine.
    }

    return false;
}