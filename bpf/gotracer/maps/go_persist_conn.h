// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

#include <gotracer/maps/handled_by_go.h>

// net/http writes a client request from persistConn.writeLoop, a different
// goroutine than the one running the request, so the connection can only be read
// from the netFD there. These three maps carry it back to the request:
//
//   writeLoop goroutine --> persistConn   (go_persist_conn_writer)
//   persistConn         --> connection    (go_persist_conn_info)
//   request goroutine   --> persistConn   (go_persist_conn_request)
//
// Reading it off persistConn.conn instead only works while the application does
// not wrap net.Conn.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // the goroutine writing the request
    __type(value, u64);         // the persistConn it writes for
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_persist_conn_writer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);                 // the persistConn
    __type(value, connection_info_t); // its connection, as read from the netFD
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_persist_conn_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // the goroutine running the request
    __type(value, u64);         // the persistConn serving it
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_persist_conn_request SEC(".maps");

static __always_inline void store_persist_conn_writer(const go_addr_key_t *g_key, u64 pc) {
    bpf_map_update_elem(&go_persist_conn_writer, g_key, &pc, BPF_ANY);
}

static __always_inline void store_persist_conn_request(const go_addr_key_t *g_key, u64 pc) {
    bpf_map_update_elem(&go_persist_conn_request, g_key, &pc, BPF_ANY);
}

// Called where the connection is known: publishes it for the request goroutine and
// claims it, since the roundTrip probes report this request.
static __always_inline void persist_conn_publish(const go_addr_key_t *g_key,
                                                 const connection_info_t *conn) {
    const u64 *pc = bpf_map_lookup_elem(&go_persist_conn_writer, g_key);
    if (!pc) {
        return;
    }

    bpf_map_update_elem(&go_persist_conn_info, pc, conn, BPF_ANY);
    bpf_map_delete_elem(&go_persist_conn_writer, g_key);
    store_go_handled_connection_info(conn);
}

static __always_inline connection_info_t *persist_conn_lookup(const go_addr_key_t *g_key) {
    const u64 *pc = bpf_map_lookup_elem(&go_persist_conn_request, g_key);
    if (!pc) {
        return NULL;
    }

    return bpf_map_lookup_elem(&go_persist_conn_info, pc);
}
