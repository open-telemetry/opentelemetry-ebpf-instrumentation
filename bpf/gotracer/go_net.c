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

#include <common/connection_info.h>
#include <common/protocol_defs.h>

#include <generictracer/k_tracer_defs.h>

#include <gotracer/go_common.h>
#include <gotracer/go_offsets.h>
#include <gotracer/go_kafka_common.h>

#include <logger/bpf_dbg.h>

#include <maps/tp_char_buf_mem.h>

typedef struct net_args {
    u64 byte_ptr;
    pid_connection_info_t p_conn;
} net_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_addr_key_t); // goroutine
    __type(value, net_args_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ongoing_fd_reads SEC(".maps");

SEC("uprobe/netFdRead")
int obi_netFdRead(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc netFD read goroutine %lx === ", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    u64 id = bpf_get_current_pid_tgid();
    void *fd_ptr = GO_PARAM1(ctx);

    // lookup active HTTP connection
    connection_info_t *conn = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
    if (conn) {
        if (conn->d_port == 0 && conn->s_port == 0) {
            bpf_dbg_printk(
                "Found existing server connection, parsing FD information for socket tuples, %llx",
                goroutine_addr);

            get_conn_info_from_fd(fd_ptr, conn); // ok to not check the result, we leave it as 0
        }
        //dbg_print_http_connection_info(conn);
    }
    // lookup a grpc connection
    // Sets up the connection info to be grabbed and mapped over the transport to operateHeaders
    void *tr = bpf_map_lookup_elem(&ongoing_grpc_operate_headers, &g_key);
    bpf_dbg_printk("tr %llx", tr);
    if (tr) {
        grpc_transports_t *t = bpf_map_lookup_elem(&ongoing_grpc_transports, tr);
        bpf_dbg_printk("t %llx", t);
        if (t) {
            if (t->conn.d_port == 0 && t->conn.s_port == 0) {
                get_conn_info_from_fd(fd_ptr,
                                      &t->conn); // ok to not check the result, we leave it as 0
            }
        }
    }
    // lookup active sql connection
    sql_func_invocation_t *sql_conn = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
    bpf_dbg_printk("sql_conn %llx", sql_conn);
    if (sql_conn) {
        get_conn_info_from_fd(fd_ptr,
                              &sql_conn->conn); // ok to not check the result, we leave it as 0
    }

    mongo_go_client_req_t *mongo_conn = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    bpf_dbg_printk("mongo_conn %llx", mongo_conn);
    if (mongo_conn) {
        get_conn_info_from_fd(fd_ptr,
                              &mongo_conn->conn); // ok to not check the result, we leave it as 0
    }

    if (conn || tr || mongo_conn || sql_conn) {
        return 0;
    }

    if (handled_kafka_request(&g_key)) {
        return 0;
    }

    // not a handled request, use the kprobes infrastructure
    void *byte_addr = GO_PARAM2(ctx);
    net_args_t net_args = {
        .byte_ptr = (u64)byte_addr,
    };
    get_conn_info_from_fd(fd_ptr,
                          &net_args.p_conn.conn); // ok to not check the result, we leave it as 0

    // Setup information for the TC context propagation.
    // We need the PID id to be able to query ongoing_http and update
    // the span id with the SEQ/ACK pair.

    egress_key_t e_key = {
        .d_port = net_args.p_conn.conn.d_port,
        .s_port = net_args.p_conn.conn.s_port,
    };

    sort_egress_key(&e_key);

    void *r = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);
    if (r) {
        return 0;
    }

    net_args.p_conn.pid = pid_from_pid_tgid(id);

    //dbg_print_http_connection_info(&net_args.p_conn.conn);
    bpf_map_update_elem(&ongoing_fd_reads, &g_key, &net_args, BPF_ANY);

    return 0;
}

SEC("uprobe/netFdReadRet")
int obi_netFdReadRet(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc netFD read returns goroutine %lx === ", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    net_args_t *net_ptr = bpf_map_lookup_elem(&ongoing_fd_reads, &g_key);
    if (!net_ptr || !net_ptr->byte_ptr) {
        return 0;
    }

    u64 bytes = net_ptr->byte_ptr;

    u64 len = (u64)GO_PARAM1(ctx);
    if (bytes && len > 0) {
        u8 *buf = tp_char_buf();
        if (buf) {
            u64 size = len;
            bpf_clamp_umax(size, TRACE_BUF_SIZE);
            bpf_probe_read(buf, size, (void *)bytes);
            bpf_dbg_printk("%d %s", size, buf);

            //dbg_print_http_connection_info(&net_ptr->p_conn.conn);

            u16 orig_dport = net_ptr->p_conn.conn.d_port;
            sort_connection_info(&net_ptr->p_conn.conn);

            //dbg_print_http_connection_info(&net_ptr->p_conn.conn);

            handle_buf_with_connection(
                ctx, &net_ptr->p_conn, (u64)goroutine_addr, buf, len, NO_SSL, TCP_RECV, orig_dport);
        }
    }

    bpf_map_delete_elem(&ongoing_fd_reads, &g_key);

    return 0;
}

static __always_inline u8 already_handled_request(void *goroutine_addr) {
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *r = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
    if (r) {
        return 1;
    }

    r = bpf_map_lookup_elem(&ongoing_http_client_requests_data, &g_key);
    if (r) {
        return 0;
    }

    r = bpf_map_lookup_elem(&ongoing_grpc_operate_headers, &g_key);
    if (r) {
        return 1;
    }

    r = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
    if (r) {
        return 1;
    }

    r = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    if (r) {
        return 1;
    }

    if (handled_kafka_request(&g_key)) {
        return 1;
    }
    return 0;
}

SEC("uprobe/netFdWrite")
int obi_netFdWrite(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc netFD write goroutine %lx === ", goroutine_addr);

    if (already_handled_request(goroutine_addr)) {
        return 0;
    }

    void *fd_ptr = GO_PARAM1(ctx);
    u8 *bytes = GO_PARAM2(ctx);
    u64 len = (u64)GO_PARAM3(ctx);
    if (bytes && len > 0) {
        u8 *buf = tp_char_buf();
        if (buf) {
            u64 size = len;
            u64 id = bpf_get_current_pid_tgid();

            bpf_clamp_umax(size, TRACE_BUF_SIZE);

            bpf_probe_read(buf, size, bytes);
            bpf_dbg_printk("%d %s", size, buf);

            pid_connection_info_t p_conn = {0};

            if (!get_conn_info_from_fd(fd_ptr, &p_conn.conn)) {
                return 0;
            }
            p_conn.pid = pid_from_pid_tgid(id);

            egress_key_t e_key = {
                .d_port = p_conn.conn.d_port,
                .s_port = p_conn.conn.s_port,
            };

            sort_egress_key(&e_key);

            void *r = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);
            if (r) {
                return 0;
            }

            u16 orig_dport = p_conn.conn.d_port;
            sort_connection_info(&p_conn.conn);

            handle_buf_with_connection(
                ctx, &p_conn, (u64)goroutine_addr, buf, len, NO_SSL, TCP_SEND, orig_dport);
        }
    }

    return 0;
}
