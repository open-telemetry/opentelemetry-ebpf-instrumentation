// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/ssl_args.h>
#include <common/trace_key.h>
#include <common/trace_lifecycle.h>

#include <generictracer/k_tracer_defs.h>
#include <generictracer/protocol_http.h>

#include <generictracer/maps/pid_tid_to_conn.h>
#include <generictracer/maps/ssl_to_pid_tid.h>
#include <generictracer/tls_prefix.h>

#include <maps/ssl_to_conn.h>

#include <logger/bpf_dbg.h>

static __always_inline void
finish_possible_delayed_tls_http_request(pid_connection_info_t *pid_conn) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info && info->submitted) {
        finish_http(info, pid_conn, NULL);
    }
}

// Releases the state keyed on an SSL that has reached the end of its life.
//
// Both SSL_shutdown and SSL_free lead here. SSL_free matters on its own because
// allocators reuse SSL pointers quickly, so a runtime that opens a connection
// per request hands the same address to a new connection almost immediately.
//
// Everything here is keyed on the SSL, so releasing twice is harmless: the
// second call finds nothing left and emits no event.
static __always_inline void ssl_release_connection_state(u64 id, void *s) {
    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &s);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn);
        bpf_map_delete_elem(&active_ssl_connections, &s_conn->p_conn);
    }

    bpf_map_delete_elem(&ssl_to_conn, &s);
    bpf_map_delete_elem(&ssl_to_pid_tid, &s);
    ssl_bios_forget(pid_from_pid_tgid(id), s);
}

// Releases the fallback binding this thread left behind, for SSL_shutdown only.
//
// pid_tid_to_conn is keyed on the thread, and a thread can free one SSL while
// another is still in flight on it.
static __always_inline void ssl_release_thread_state(u64 id) {
    bpf_map_delete_elem(&pid_tid_to_conn, &id);
}

static __always_inline void
handle_ssl_buf(void *ctx, u64 id, ssl_args_t *args, int bytes_len, u8 direction) {
    if (args) {
        void *ssl = ((void *)args->ssl);
        const u64 ssl_ptr = (u64)ssl;
        bpf_dbg_printk("SSL_buf id=%d ssl=%llx", id, ssl);
        ssl_pid_connection_info_t *conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);

        if (!conn) {
            conn = bpf_map_lookup_elem(&pid_tid_to_conn, &id);

            if (!conn) {
                // We try even harder, we might have an SSL pointer mapped on another
                // thread, since tcp_rcv_established was handled on another thread pool.
                // First we look up a pid_tid by the ssl pointer, which might've been established
                // by a prior SSL_read on another thread, then we look up in the same map.
                // Clean-up here we are done trying if we don't succeed
                u64 *pid_tid_ptr = bpf_map_lookup_elem(&ssl_to_pid_tid, &ssl_ptr);

                if (pid_tid_ptr) {
                    const u64 pid_tid = *pid_tid_ptr;

                    conn = bpf_map_lookup_elem(&pid_tid_to_conn, &pid_tid);
                    bpf_dbg_printk(
                        "Separate pool lookup ssl=%llx, pid=%d, conn=%llx", ssl_ptr, pid_tid, conn);
                } else {
                    bpf_dbg_printk("Other thread lookup failed for ssl=%llx", ssl_ptr);
                }
            }

            // If we found a connection setup by tcp_rcv_established, which means
            // we missed a SSL_do_handshake, update our ssl to connection map to be
            // used by the rest of the SSL lifecycle. We shouldn't rely on the SSL_write
            // being on the same thread as the SSL_read.
            if (conn) {
                bpf_map_delete_elem(&pid_tid_to_conn, &id);
                ssl_pid_connection_info_t c;
                bpf_probe_read(&c, sizeof(ssl_pid_connection_info_t), conn);
                bpf_map_update_elem(&ssl_to_conn, &ssl, &c, BPF_ANY);
            }
        }

        bpf_map_delete_elem(&ssl_to_pid_tid, &ssl_ptr);

        if (bytes_len <= 0) {
            return;
        }

        if (!conn) {
            // At this point the threading in the language doesn't allow us to properly match the SSL* with
            // the connection info. We send partial event, at least we can find the path, timing and response.
            // even though we won't have peer information.
            ssl_pid_connection_info_t p_c = {};
            bpf_dbg_printk("setting fake connection info ssl=%llx", ssl);
            __builtin_memcpy(&p_c.p_conn.conn.s_addr, &ssl, sizeof(void *));
            p_c.p_conn.conn.d_port = p_c.p_conn.conn.s_port = p_c.orig_dport = 0;
            p_c.p_conn.pid = pid_from_pid_tgid(id);

            bpf_map_update_elem(&ssl_to_conn, &ssl, &p_c, BPF_ANY);
            conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
        }

        if (conn) {
            bpf_dbg_printk("SSL conn");
            dbg_print_http_connection_info(&conn->p_conn.conn);

            // must be last, doesn't return
            handle_buf_with_connection(ctx,
                                       &conn->p_conn,
                                       (void *)args->buf,
                                       bytes_len,
                                       WITH_SSL,
                                       direction,
                                       conn->orig_dport,
                                       // A TLS uprobe holds no socket.
                                       0);
        } else {
            bpf_dbg_printk("No connection info! This is a bug.");
        }
    }
}
