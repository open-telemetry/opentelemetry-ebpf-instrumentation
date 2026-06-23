// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/ssl_helpers.h>

#include <maps/active_ssl_read_args.h>
#include <maps/active_ssl_write_args.h>

#include <pid/pid_helpers.h>

#include <socktracer/common_defs.h>
#include <socktracer/socket_data.h>

enum : unsigned char {
    k_tls_content_type_handshake = 0x16,
    k_tls_version_major = 0x03,
    k_tls_handshake_client_hello = 0x01,
    k_tls_handshake_server_hello = 0x02,
    k_tls_handshake_type_offset = 5,
    k_tls_handshake_min_len = 6,
};

// Returns true if the first bytes of ctx look like a TLS ClientHello or ServerHello.
// Used to detect new TLS connections before SSL_read/SSL_write uprobes fire.
static __always_inline bool ctx_is_tls_handshake(void *ctx) {
    ctx_pull_data(ctx, k_tls_handshake_min_len);

    const unsigned char *data = ctx_data(ctx);
    const unsigned char *end = ctx_data_end(ctx);

    if (data + k_tls_handshake_min_len > end) {
        return false;
    }

    if (data[0] != k_tls_content_type_handshake || data[1] != k_tls_version_major) {
        return false;
    }

    const unsigned char handshake_type = data[k_tls_handshake_type_offset];

    return handshake_type == k_tls_handshake_client_hello ||
           handshake_type == k_tls_handshake_server_hello;
}

// Bridges an SSL connection to its socket connection info so that the SSL uprobe path
// (generictracer) can look it up by SSL* and emit spans with correct connection metadata.
// Must only be called from egress (sk_msg), which runs in process context during SSL_write
// when active_ssl_write_args is populated. Only bridges client sockets — servers are handled
// differently (ingress path accepts the connection and already has full info).
static __always_inline void maybe_bridge_ssl_conn(const struct socket_data *sk_data) {
    if (sk_data->sk_type != sk_type_client) {
        return;
    }

    pid_connection_info_t p_conn = {};
    p_conn.pid = pid_from_pid_tgid(sk_data->pid_tgid);
    p_conn.conn = sk_data->sorted_conn;

    connect_ssl_to_connection(sk_data->pid_tgid, &p_conn, TCP_SEND, sk_data->conn.d_port);
}

// Egress (sk_msg): runs in process context on the same thread as SSL_write.
static __always_inline bool sk_data_is_ssl_egress(struct socket_data *sk_data, void *ctx) {
    if (sk_data->ssl_state == ssl_state_yes) {
        return true;
    }

    ssl_args_t *ssl_args = bpf_map_lookup_elem(&active_ssl_write_args, &sk_data->pid_tgid);

    if (ssl_args) {
        sk_data->ssl_state = ssl_state_yes;
        maybe_bridge_ssl_conn(sk_data);
        return true;
    }

    if (ctx_is_tls_handshake(ctx)) {
        sk_data->ssl_state = ssl_state_yes;
        maybe_bridge_ssl_conn(sk_data);
        return true;
    }

    return false;
}

// Ingress (sk_skb/stream_verdict): runs in softirq context.
static __always_inline bool sk_data_is_ssl_ingress(struct socket_data *sk_data,
                                                   struct __sk_buff *skb) {
    switch (sk_data->ssl_state) {
    case ssl_state_yes:
        return true;
    case ssl_state_no:
        return false;
    case ssl_state_unknown:
        break;
    }

    ssl_args_t *ssl_args = bpf_map_lookup_elem(&active_ssl_read_args, &sk_data->pid_tgid);

    if (ssl_args) {
        sk_data->ssl_state = ssl_state_yes;
        return true;
    }

    if (ctx_is_tls_handshake(skb)) {
        sk_data->ssl_state = ssl_state_yes;
        return true;
    }

    // Leave ssl_state_unknown — softirq context is not definitive.
    return false;
}
