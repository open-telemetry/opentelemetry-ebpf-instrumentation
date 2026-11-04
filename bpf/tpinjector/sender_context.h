// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>
#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>
#include <pid/types/pid_info.h>

typedef struct {
    pid_connection_info_t p_conn;
    tp_info_t parent;
    u64 id;
    u64 started_ns;
    u64 process_start;
    pid_info_t pid;
    u8 parent_status;
    u8 _pad[3];
} skmsg_sender_context_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, skmsg_sender_context_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} skmsg_senders SEC(".maps");

// Socket pointers identify the exact lifetime, including across network namespaces.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, u8);
    __uint(pinning, OBI_PIN_INTERNAL);
} skmsg_client_owners SEC(".maps");

static __always_inline bool skmsg_sender_matches(const skmsg_sender_context_t *sender,
                                                 const pid_connection_info_t *conn,
                                                 u64 id,
                                                 u64 now,
                                                 u64 max_age) {
    return sender && sender->id == id && sender->p_conn.pid == (u32)(id >> 32) &&
           sender->p_conn.pid == conn->pid && sender->started_ns <= now &&
           now - sender->started_ns <= max_age &&
           bpf_memcmp(&sender->p_conn.conn, &conn->conn, sizeof(conn->conn)) == 0;
}
