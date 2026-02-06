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
#include <bpfcore/bpf_builtins.h>

#include <gotracer/go_common.h>

#include <logger/bpf_dbg.h>

SEC("uprobe/netFdRead")
int obi_uprobe_netFdRead(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/netFdRead goroutine_addr=%lx === ", goroutine_addr);

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
                                      &t->conn); // ok to not check the result, we leave it as 0
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
                              &sql_conn->conn); // ok to not check the result, we leave it as 0
        return 0;
    }

    mongo_go_client_req_t *mongo_conn = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    bpf_dbg_printk("mongo_conn=%llx", mongo_conn);
    if (mongo_conn) {
        void *fd_ptr = GO_PARAM1(ctx);
        get_conn_info_from_fd(fd_ptr,
                              &mongo_conn->conn); // ok to not check the result, we leave it as 0

        return 0;
    }

    // lookup active HTTP connection
    connection_info_t *conn = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
    if (conn) {
        if (conn->d_port == 0 && conn->s_port == 0) {
            bpf_dbg_printk("Found existing server connection, parsing FD information for socket "
                           "tuples, goroutine_addr=%llx",
                           goroutine_addr);

            void *fd_ptr = GO_PARAM1(ctx);
            get_conn_info_from_fd(fd_ptr, conn); // ok to not check the result, we leave it as 0
        }
        //dbg_print_http_connection_info(conn);
        return 0;
    }

    return 0;
}