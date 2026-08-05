// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <generictracer/http2_server_hpack.h>
#include <generictracer/maps/http2_server_hpack_states.h>

static __always_inline http2_server_hpack_state_t *empty_http2_server_hpack_state() {
    http2_server_hpack_state_t *state = http2_server_hpack_state_mem();
    if (state) {
        hpack_dynamic_name_state_init(&state->dynamic);
        h2_hpack_stream_reset(&state->headers);
        h2_request_frame_cursor_reset(&state->request_cursor);
        state->desynced = 0;
        __builtin_memset(state->_pad, 0, sizeof(state->_pad));
    }
    return state;
}

static __always_inline http2_server_hpack_state_t *
lookup_http2_server_hpack_state(const http2_server_hpack_lease_key_t *key) {
    return key ? bpf_map_lookup_elem(&http2_server_hpack_states, key) : NULL;
}

static __always_inline u8 insert_http2_server_hpack_state(const http2_server_hpack_lease_key_t *key,
                                                          u8 desynced) {
    http2_server_hpack_state_t *state = empty_http2_server_hpack_state();
    if (!key || !state) {
        return 0;
    }
    if (desynced) {
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
    }
    return bpf_map_update_elem(&http2_server_hpack_states, key, state, BPF_NOEXIST) == 0;
}

static __always_inline http2_server_hpack_state_t *
recover_http2_server_hpack_state(const http2_server_hpack_lease_key_t *key) {
    (void)insert_http2_server_hpack_state(key, 1);
    http2_server_hpack_state_t *state = lookup_http2_server_hpack_state(key);
    if (state) {
        state->desynced = 1;
        hpack_dynamic_name_state_invalidate(&state->dynamic);
    }
    return state;
}

static __always_inline void
poison_http2_server_hpack_state(const http2_server_hpack_lease_key_t *key) {
    http2_server_hpack_state_t *state = lookup_http2_server_hpack_state(key);
    if (state) {
        // Nonowners may only publish this aligned monotonic flag. The lease
        // owner invalidates the multi-field dynamic table after observing it.
        state->desynced = 1;
    }
}

static __always_inline void
retire_http2_server_hpack_generation(const http2_server_hpack_lease_key_t *key) {
    if (!key) {
        return;
    }
    http2_conn_info_data_t *raw = bpf_map_lookup_elem(&ongoing_http2_connections, &key->pid_conn);
    if (raw && http2_server_hpack_generation_matches(key, &key->pid_conn, raw)) {
        // This aligned generation-local tombstone is monotonic. It remains
        // authoritative even if the larger HPACK state is evicted.
        raw->retired = 1;
    }
    poison_http2_server_hpack_state(key);
    poison_http2_server_hpack_lease(key);
}

static __always_inline void
delete_http2_server_hpack_state(const pid_connection_info_t *pid_conn,
                                const http2_conn_info_data_t *connection) {
    if (!pid_conn || !connection) {
        return;
    }
    const http2_server_hpack_lease_key_t key = http2_server_hpack_lease_key(pid_conn, connection);
    const u64 token = new_http2_server_hpack_lease_token();
    if (!claim_http2_server_hpack_lease(&key, token)) {
        retire_http2_server_hpack_generation(&key);
        return;
    }
    http2_conn_info_data_t *raw = bpf_map_lookup_elem(&ongoing_http2_connections, pid_conn);
    if (raw && http2_server_hpack_generation_matches(&key, pid_conn, raw)) {
        raw->retired = 1;
        bpf_map_delete_elem(&ongoing_http2_connections, pid_conn);
    }
    bpf_map_delete_elem(&http2_server_hpack_states, &key);
    release_http2_server_hpack_lease(&key, token);
}
