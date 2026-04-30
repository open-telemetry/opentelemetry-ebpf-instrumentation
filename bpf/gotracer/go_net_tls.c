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

#include <gotracer/go_common.h>
#include <gotracer/maps/ongoing_ssl_ops.h>

#include <gotracer/types/net_args.h>

#include <gotracer/go_net_common.h>

#include <logger/bpf_dbg.h>

SEC("uprobe/cryptoTlsRead")
int obi_uprobe_cryptoTlsRead(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *conn = GO_PARAM1(ctx);
    void *buf = GO_PARAM2(ctx);

    bpf_printk("=== uprobe/cryptoTlsRead goroutine_addr=%lx, c=%llx, buf=%llx === ",
               goroutine_addr,
               conn,
               buf);

    if (!buf) {
        return 0;
    }

    net_args_t args = {0};

    void *conn_conn = 0;
    bpf_probe_read(&conn_conn, sizeof(conn_conn), conn + 8); // 8 skip embedded data structure class
    bpf_dbg_printk("unwrapped conn %llx", conn_conn);
    if (conn_conn) {
        void *fd_ptr = fd_ptr_from_conn(conn_conn);

        bpf_dbg_printk("found fd_ptr %llx", fd_ptr);

        if (already_handled_goroutine(&g_key, fd_ptr)) {
            return 0;
        }

        if (!get_conn_info(conn_conn, &args.p_conn.conn)) {
            bpf_dbg_printk("cannot read connection info from %llx", conn_conn);
            return 0;
        }
        const u64 id = bpf_get_current_pid_tgid();
        args.p_conn.pid = pid_from_pid_tgid(id);
        args.byte_ptr = (u64)buf;

        dbg_print_http_connection_info(&args.p_conn.conn);

        bpf_map_update_elem(&ongoing_ssl_ops, &g_key, &args, BPF_ANY);
    }

    return 0;
}

SEC("uprobe/cryptoTlsRead")
int obi_uprobe_cryptoTlsReadRet(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    u64 len = (u64)GO_PARAM1(ctx);
    void *err = GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/cryptoTlsRead returns goroutine_addr=%lx, size=%d, err=%llx === ",
                   goroutine_addr,
                   len,
                   err);

    if (len == 0 || err != 0) {
        goto done;
    }

    net_args_t *args = bpf_map_lookup_elem(&ongoing_ssl_ops, &g_key);
    if (args) {
        bpf_printk("buf = %s", args->byte_ptr);
    }

done:
    bpf_map_delete_elem(&ongoing_ssl_ops, &g_key);

    return 0;
}

SEC("uprobe/cryptoTlsWrite")
int obi_uprobe_cryptoTlsWrite(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_dbg_printk("=== uprobe/cryptoTlsWrite goroutine_addr=%lx, c=%llx, buf=%llx === ",
                   goroutine_addr,
                   GO_PARAM1(ctx),
                   GO_PARAM2(ctx));

    net_args_t args = {0};
    bpf_map_update_elem(&ongoing_ssl_ops, &g_key, &args, BPF_ANY);

    return 0;
}

SEC("uprobe/cryptoTlsWrite")
int obi_uprobe_cryptoTlsWriteRet(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_dbg_printk("=== uprobe/cryptoTlsWrite returns goroutine_addr=%lx", goroutine_addr);

    bpf_map_delete_elem(&ongoing_ssl_ops, &g_key);
    return 0;
}
