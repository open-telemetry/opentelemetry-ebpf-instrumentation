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

#include <gotracer/go_offsets.h>

#include <gotracer/go_common.h>
#include <gotracer/go_large_buffer.h>
#include <gotracer/maps/ongoing_ssl_ops.h>

#include <gotracer/types/net_args.h>

#include <gotracer/go_net_common.h>

#include <logger/bpf_dbg.h>

static __always_inline void *unwrap_conn(void *conn) {
    void *conn_conn = 0;
    bpf_probe_read(&conn_conn, sizeof(conn_conn), conn + k_go_iface_data_offset);
    bpf_dbg_printk("unwrapped conn %llx", conn_conn);

    return conn_conn;
}

SEC("uprobe/cryptoTlsRead")
int obi_uprobe_cryptoTlsRead(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *conn = GO_PARAM1(ctx);
    const void *buf = GO_PARAM2(ctx);

    bpf_dbg_printk("=== uprobe/cryptoTlsRead goroutine_addr=%lx, c=%llx, buf=%llx === ",
                   goroutine_addr,
                   conn,
                   buf);

    if (!buf) {
        return 0;
    }

    net_args_t args = {0};

    void *conn_conn = unwrap_conn(conn);
    if (conn_conn) {
        void *fd_ptr = fd_ptr_from_conn(conn_conn);

        bpf_dbg_printk("found fd_ptr %llx", fd_ptr);

        if (!fd_ptr) {
            return 0;
        }

        if (already_handled_goroutine(&g_key, fd_ptr)) {
            if (!http_large_buffers_enabled()) {
                return 0;
            }
            args.skip = 1;
        }

        if (!get_conn_info_from_fd(fd_ptr, &args.p_conn.conn, false)) {
            bpf_dbg_printk("cannot read connection info from %llx", conn_conn);
            return 0;
        }

        const u64 id = bpf_get_current_pid_tgid();
        args.p_conn.pid = pid_from_pid_tgid(id);
        args.byte_ptr = (u64)buf;

        dbg_print_http_connection_info(&args.p_conn.conn);

        pid_connection_info_t p_conn = args.p_conn;

        sort_connection_info(&p_conn.conn);

        if (already_handled_request_sorted(&p_conn.conn)) {
            cleanup_duplicate_generic_events_sorted(&p_conn);
            if (!http_large_buffers_enabled()) {
                return 0;
            }

            args.skip = 1;
            bpf_d_printk("skipping");
        }

        bpf_map_update_elem(&ongoing_ssl_ops, &g_key, &args, BPF_ANY);
    }

    return 0;
}

SEC("uprobe/cryptoTlsRead")
int obi_uprobe_cryptoTlsReadRet(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    const u64 len = (u64)GO_PARAM1(ctx);
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
        bpf_dbg_printk("buf = %s", args->byte_ptr);

        if (!args->byte_ptr || args->skip) {
            if (http_large_buffer_skip(len)) {
                goto done;
            } else if (args->byte_ptr) {
                send_http_large_buffers_if_needed(
                    &g_key, &args->p_conn.conn, (void *)args->byte_ptr, len, TCP_RECV);
            }

            goto done;
        }

        const u16 orig_dport = args->p_conn.conn.d_port;
        sort_connection_info(&args->p_conn.conn);

        dbg_print_http_connection_info(&args->p_conn.conn);

        // we don't need to mark the connection as SSL, the kprobes on send/receive
        // never fire for Go programs, we are just calling the buffer handling.

        bpf_map_delete_elem(&ongoing_ssl_ops, &g_key);
        // doesn't return
        handle_light_weight_thread_buf(ctx,
                                       (lw_thread_t)goroutine_addr,
                                       (protocol_selector_t){.http = 1, .http2 = 0, .tcp = 1},
                                       &args->p_conn,
                                       (void *)args->byte_ptr,
                                       len,
                                       WITH_SSL,
                                       TCP_RECV,
                                       orig_dport);
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

    void *c = GO_PARAM1(ctx);
    void *buf = GO_PARAM2(ctx);
    const u64 len = (u64)GO_PARAM3(ctx);

    bpf_dbg_printk("=== uprobe/cryptoTlsWrite goroutine_addr=%lx, c=%llx, buf=%llx === ",
                   goroutine_addr,
                   c,
                   buf);

    if (!buf || len <= 0) {
        return 0;
    }

    bpf_dbg_printk("[%d] buf=%s", len, buf);

    net_args_t args = {0};

    void *conn_conn = unwrap_conn(c);
    if (conn_conn) {
        void *fd_ptr = fd_ptr_from_conn(conn_conn);

        bpf_dbg_printk("found fd_ptr %llx", fd_ptr);

        if (!fd_ptr) {
            return 0;
        }

        if (already_handled_goroutine(&g_key, fd_ptr)) {
            if (!http_large_buffers_enabled()) {
                return 0;
            }
            args.skip = 1;
        }

        if (!get_conn_info_from_fd(fd_ptr, &args.p_conn.conn, false)) {
            bpf_dbg_printk("cannot read connection info from %llx", conn_conn);
            return 0;
        }
        const u64 id = bpf_get_current_pid_tgid();
        args.p_conn.pid = pid_from_pid_tgid(id);
        args.byte_ptr = (u64)buf;

        if (args.skip) {
            send_http_large_buffers_if_needed(&g_key, &args.p_conn.conn, buf, len, TCP_SEND);
            return 0;
        }

        dbg_print_http_connection_info(&args.p_conn.conn);

        // we store this ongoing_ssl_ops, so the non TLS probes on netFD (go_net.c)
        // skip this work. the return probes clean up
        bpf_map_update_elem(&ongoing_ssl_ops, &g_key, &args, BPF_ANY);

        u16 orig_dport = args.p_conn.conn.d_port;
        sort_connection_info(&args.p_conn.conn);

        if (already_handled_request_sorted(&args.p_conn.conn)) {
            cleanup_duplicate_generic_events_sorted(&args.p_conn);
            if (!http_large_buffer_skip(len)) {
                send_http_large_buffers_if_needed(&g_key, &args.p_conn.conn, buf, len, TCP_SEND);
            }
            return 0;
        }

        // we don't need to mark the connection as SSL, the kprobes on send/receive
        // never fire for Go programs, we are just calling the buffer handling.

        // doesn't return
        handle_light_weight_thread_buf(ctx,
                                       (lw_thread_t)goroutine_addr,
                                       (protocol_selector_t){.http = 1, .http2 = 0, .tcp = 1},
                                       &args.p_conn,
                                       buf,
                                       len,
                                       WITH_SSL,
                                       TCP_SEND,
                                       orig_dport);
    }

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
