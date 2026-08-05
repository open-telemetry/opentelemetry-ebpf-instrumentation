// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/protocol_http2_helpers.h>

#include <generictracer/maps/http2_server_hpack_leases.h>

static __always_inline http2_server_hpack_lease_key_t http2_server_hpack_lease_key(
    const pid_connection_info_t *pid_conn, const http2_conn_info_data_t *connection) {
    http2_server_hpack_lease_key_t key = {};
    if (pid_conn) {
        key.pid_conn = *pid_conn;
    }
    if (connection) {
        key.connection_id = connection->id;
        key.process_start_time = connection->process_start_time;
        key.connection_time = connection->connection_time;
    }
    return key;
}

static __always_inline u8
http2_server_hpack_generation_matches(const http2_server_hpack_lease_key_t *key,
                                      const pid_connection_info_t *pid_conn,
                                      const http2_conn_info_data_t *connection) {
    return key && pid_conn && connection && key->connection_id == connection->id &&
           key->process_start_time == connection->process_start_time &&
           key->connection_time == connection->connection_time &&
           key->pid_conn.pid == pid_conn->pid &&
           bpf_memcmp(&key->pid_conn.conn, &pid_conn->conn, sizeof(pid_conn->conn)) == 0;
}

static __always_inline u64 new_http2_server_hpack_lease_token() {
    u64 token =
        bpf_ktime_get_ns() ^ bpf_get_current_pid_tgid() ^ ((u64)bpf_get_prandom_u32() << 32);
    return token ? token : 1;
}

static __always_inline u8 claim_http2_server_hpack_lease(const http2_server_hpack_lease_key_t *key,
                                                         u64 token) {
    const http2_server_hpack_lease_t candidate = {
        .token = token,
    };
    return key && token &&
           bpf_map_update_elem(&http2_server_hpack_leases, key, &candidate, BPF_NOEXIST) == 0;
}

static __always_inline void
release_http2_server_hpack_lease(const http2_server_hpack_lease_key_t *key, u64 token) {
    if (!key || !token) {
        return;
    }
    http2_server_hpack_lease_t *lease = bpf_map_lookup_elem(&http2_server_hpack_leases, key);
    if (lease && lease->token == token) {
        bpf_map_delete_elem(&http2_server_hpack_leases, key);
    }
}

static __always_inline void
poison_http2_server_hpack_lease(const http2_server_hpack_lease_key_t *key) {
    http2_server_hpack_lease_t *lease = bpf_map_lookup_elem(&http2_server_hpack_leases, key);
    if (lease) {
        // Aligned word stores are atomic. Only the owner mutates HPACK state;
        // contenders can merely force that owner to discard its transaction.
        lease->poisoned = 1;
    }
}
