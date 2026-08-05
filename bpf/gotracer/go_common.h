// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

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

#pragma once

#include <bpfcore/compiler.h>
#include <bpfcore/utils.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/process_incarnation.h>
#include <common/scratch_mem.h>
#include <common/strings.h>
#include <common/trace_helpers.h>
#include <common/trace_util.h>
#include <common/tracing.h>
#include <common/tp_info.h>

#include <gotracer/go_offsets.h>

#include <gotracer/maps/handled_by_go.h>

#include <logger/bpf_dbg.h>

#include <maps/incoming_trace_map.h>

#include <pid/pid_helpers.h>
#include <pid/maps/map_sizing.h>

enum {
    W3C_KEY_LENGTH = 11,
    W3C_VAL_LENGTH = 55,
    k_go_meta_headers_max_fields = 32,
};

static unsigned char tp_encoded[] = {
    0x4d, 0x83, 0x21, 0x6b, 0x1d, 0x85, 0xa9, 0x3f}; // hpack encoded "traceparent"

// Temporary information about a function invocation. It stores the invocation time of a function
// as well as the value of registers at the invocation time. This way we can retrieve them at the
// return uprobes so we can know the values of the function arguments (which are passed as registers
// since Go 1.17).
// This element is created in the function start probe and stored in the ongoing_http_requests hashmaps.
// Then it is retrieved in the return uprobes and used to know the HTTP call duration as well as its
// attributes (method, path, and status code).

typedef struct goroutine_metadata_t {
    go_addr_key_t parent;
    u64 timestamp;
    u64 generation;
} goroutine_metadata;

typedef struct go_server_connection {
    connection_info_t conn;
    u32 _pad;
    u64 generation;
} go_server_connection_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);        // key: pointer to the goroutine
    __type(value, goroutine_metadata); // value: timestamp of the goroutine creation
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ongoing_goroutines SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, go_server_connection_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ongoing_server_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_client_connections SEC(".maps");

typedef struct go_trace_owner {
    u64 span_addr;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
} go_trace_owner_t;

typedef struct go_process_addr_key {
    u64 pid;
    u64 generation;
    u64 addr;
} go_process_addr_key_t;

typedef struct go_process_key {
    u64 pid;
    u64 generation;
} go_process_key_t;

typedef struct go_process_generation {
    u64 generation;
    u64 start_time;
} go_process_generation_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // host PID
    __type(value, go_process_generation_t);
    __uint(max_entries, k_max_concurrent_pids);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_process_generations SEC(".maps");

typedef struct go_trace_state {
    tp_info_t generic_tp;
    go_trace_owner_t owner;
    u8 has_generic;
    u8 has_owner;
    u8 poisoned;
    u8 _pad[5];
} go_trace_state_t;

typedef struct go_trace_owner_link {
    go_process_addr_key_t goroutine;
    go_trace_owner_t owner;
    go_trace_owner_t previous;
    u8 has_previous;
    u8 _pad[7];
} go_trace_owner_link_t;

typedef struct go_trace_owner_link_scratch {
    go_trace_owner_link_t current;
    go_trace_owner_link_t previous;
} go_trace_owner_link_scratch_t;

typedef struct go_trace_lease_key {
    u64 pid;
    u64 generation;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
} go_trace_lease_key_t;

typedef struct go_trace_resolve_scratch {
    go_process_addr_key_t state_key;
    go_process_addr_key_t owner_key;
    go_trace_lease_key_t lease_key;
} go_trace_resolve_scratch_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_process_addr_key_t); // key: process generation and goroutine pointer
    __type(value, go_trace_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_trace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_trace_lease_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_trace_leases SEC(".maps");

SCRATCH_MEM_TYPED(go_trace_state, go_trace_state_t);
SCRATCH_MEM_TYPED(go_trace_owner_link_scratch, go_trace_owner_link_scratch_t);
SCRATCH_MEM_TYPED(go_trace_resolve_scratch, go_trace_resolve_scratch_t);

// this is a large value data structure, increase
// concurrent_custom_spans carefully.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_process_addr_key_t); // process generation and span pointer
    __type(value, otel_span_t);
    __uint(max_entries, MAX_CONCURRENT_CUSTOM_SPANS);
    __uint(pinning, OBI_PIN_INTERNAL);
} active_spans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_process_addr_key_t); // process generation and span pointer
    __type(value, go_trace_owner_link_t);
    __uint(max_entries, MAX_CONCURRENT_CUSTOM_SPANS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_trace_owner_links SEC(".maps");

// Serialize every owner read and transition for one goroutine. Unlike the
// payload maps, claims must not be evicted while a transition is live.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_process_addr_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_trace_owner_claims SEC(".maps");

// A lifecycle reset is terminal for a claimed transition. The reset marker is
// level-triggered so either the current claimant or its releaser consumes it.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_process_addr_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_trace_state_resets SEC(".maps");

typedef struct go_trace_parent {
    tp_info_t tp;
} go_trace_parent_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: goroutine
    __type(value, void *);      // the transport *
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_operate_headers SEC(".maps");

typedef struct grpc_transports {
    connection_info_t conn;
    u8 type;
    u8 pad[3];
    tp_info_t tp;
} grpc_transports_t;

// TODO: use go_addr_key_t as key
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the transport pointer
    __type(value, grpc_transports_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_transports SEC(".maps");

#define SQL_CONN_TYPE_DATABASE_SQL 0 // database/sql (mysql, pq)
#define SQL_CONN_TYPE_PGX 1          // github.com/jackc/pgx/v5

typedef struct sql_func_invocation {
    u64 start_monotime_ns;
    u64 sql_param;
    u64 query_len;
    u64 driver_conn_ptr;
    tp_info_t tp;
    connection_info_t conn;
    u8 _pad[4];
} sql_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, sql_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_sql_queries SEC(".maps");

typedef struct grpc_header_field {
    u8 *key_ptr;
    u64 key_len;
    u8 *val_ptr;
    u64 val_len;
    u64 sensitive;
} grpc_header_field_t;

static __always_inline void
go_addr_key_from_id_and_pid(go_addr_key_t *current, void *addr, const u32 pid) {
    current->addr = (u64)addr;
    current->pid = pid;
}

static __always_inline void go_addr_key_from_id(go_addr_key_t *current, void *addr) {
    const u64 pid_tid = bpf_get_current_pid_tgid();
    const u32 pid = pid_from_pid_tgid(pid_tid);

    go_addr_key_from_id_and_pid(current, addr, pid);
}

static __always_inline u8 go_exact_process_addr_key_from_id(go_exact_process_addr_key_t *current,
                                                            void *addr) {
    if (!current) {
        return 0;
    }
    const u64 process_start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS();
    if (!process_start_time) {
        return 0;
    }
    const u32 pid = pid_from_pid_tgid(bpf_get_current_pid_tgid());
    *current = go_exact_process_addr_key(pid, process_start_time, (u64)addr);
    return 1;
}

static __always_inline u8 go_exact_process_addr_key_from_address(
    go_exact_process_addr_key_t *current, const go_addr_key_t *address) {
    return address && go_exact_process_addr_key_from_id(current, (void *)address->addr) &&
           current->address.pid == address->pid;
}

static __always_inline u8 go_exact_process_stream_key_from_id(
    go_exact_process_stream_key_t *current, void *conn_ptr, u32 stream_id) {
    if (!current) {
        return 0;
    }
    const u64 process_start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS();
    if (!process_start_time) {
        return 0;
    }
    const u32 pid = pid_from_pid_tgid(bpf_get_current_pid_tgid());
    *current = go_exact_process_stream_key(pid, process_start_time, (u64)conn_ptr, stream_id);
    return 1;
}

static __always_inline u64 go_process_generation(const u64 pid) {
    const u32 host_pid = (u32)pid;
    const go_process_generation_t *state = bpf_map_lookup_elem(&go_process_generations, &host_pid);
    return state && process_incarnation_matches_current(host_pid, state->start_time)
               ? state->generation
               : 0;
}

static __always_inline u8 go_process_generation_matches(const u64 pid, const u64 generation) {
    return process_incarnation_matches(generation, go_process_generation(pid));
}

static __always_inline void go_server_connection_clear(const go_addr_key_t *goroutine_key) {
    if (goroutine_key) {
        bpf_map_delete_elem(&ongoing_server_connections, goroutine_key);
    }
}

static __always_inline go_server_connection_t *
go_server_connection_lookup_current(const go_addr_key_t *goroutine_key) {
    if (!goroutine_key) {
        return NULL;
    }
    go_server_connection_t *state = bpf_map_lookup_elem(&ongoing_server_connections, goroutine_key);
    if (!state) {
        return NULL;
    }
    if (!go_process_generation_matches(goroutine_key->pid, state->generation)) {
        bpf_map_delete_elem(&ongoing_server_connections, goroutine_key);
        return NULL;
    }
    return state;
}

static __always_inline u8 go_server_connection_store_current(const go_addr_key_t *goroutine_key,
                                                             const connection_info_t *connection) {
    if (!goroutine_key || !connection) {
        return 0;
    }
    const u64 generation = go_process_generation(goroutine_key->pid);
    if (!generation) {
        go_server_connection_clear(goroutine_key);
        return 0;
    }
    const go_server_connection_t state = {
        .conn = *connection,
        .generation = generation,
    };
    return bpf_map_update_elem(&ongoing_server_connections, goroutine_key, &state, BPF_ANY) == 0;
}

static __always_inline u8 go_process_addr_key_from_generation(go_process_addr_key_t *current,
                                                              const go_addr_key_t *addr_key,
                                                              const u64 generation) {
    if (!current || !addr_key || !generation) {
        return 0;
    }
    current->pid = addr_key->pid;
    current->generation = generation;
    current->addr = addr_key->addr;
    return 1;
}

static __always_inline u8 go_process_addr_key_from_go_addr(go_process_addr_key_t *current,
                                                           const go_addr_key_t *addr_key) {
    return go_process_addr_key_from_generation(
        current, addr_key, go_process_generation(addr_key->pid));
}

static __always_inline u8 go_process_key_from_pid(go_process_key_t *current, const u64 pid) {
    const u64 generation = go_process_generation(pid);
    if (!current || !generation) {
        return 0;
    }
    current->pid = pid;
    current->generation = generation;
    return 1;
}

static __always_inline otel_span_t *lookup_active_span(const go_addr_key_t *span_key) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_go_addr(&key, span_key)) {
        return 0;
    }
    return bpf_map_lookup_elem(&active_spans, &key);
}

static __always_inline long
update_active_span(const go_addr_key_t *span_key, const otel_span_t *span, u64 flags) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_go_addr(&key, span_key)) {
        return -1;
    }
    return bpf_map_update_elem(&active_spans, &key, span, flags);
}

static __always_inline long delete_active_span(const go_addr_key_t *span_key) {
    go_process_addr_key_t key = {};
    if (!go_process_addr_key_from_go_addr(&key, span_key)) {
        return -1;
    }
    return bpf_map_delete_elem(&active_spans, &key);
}

enum go_trace_parent_result : s8 {
    k_go_trace_parent_error = -1,
    k_go_trace_parent_not_found = 0,
    k_go_trace_parent_found = 1,
};

enum : u64 { k_go_parent_error = ~0ULL };
enum {
    k_go_owner_restore_depth = 6,
    // BPF_EXIST is not available in every native-test stub that includes this
    // header, but its UAPI value is stable.
    k_go_trace_state_update_existing = 2,
};

static __always_inline u8 go_trace_ids_match(const unsigned char *trace_id,
                                             const unsigned char *span_id,
                                             const tp_info_t *tp) {
    return *((u64 *)trace_id) == *((u64 *)tp->trace_id) &&
           *((u64 *)(trace_id + 8)) == *((u64 *)(tp->trace_id + 8)) &&
           *((u64 *)span_id) == *((u64 *)tp->span_id);
}

static __always_inline u8 go_trace_owner_matches(const go_trace_owner_t *owner,
                                                 const tp_info_t *tp) {
    return owner->span_addr && go_trace_ids_match(owner->trace_id, owner->span_id, tp);
}

static __always_inline u8 go_trace_owners_match(const go_trace_owner_t *left,
                                                const go_trace_owner_t *right) {
    return left->span_addr == right->span_addr &&
           *((u64 *)left->trace_id) == *((u64 *)right->trace_id) &&
           *((u64 *)(left->trace_id + 8)) == *((u64 *)(right->trace_id + 8)) &&
           *((u64 *)left->span_id) == *((u64 *)right->span_id);
}

static __always_inline void
go_trace_owner_from_tp(go_trace_owner_t *owner, const tp_info_t *tp, u64 span_addr) {
    owner->span_addr = span_addr;
    *((u64 *)owner->trace_id) = *((u64 *)tp->trace_id);
    *((u64 *)(owner->trace_id + 8)) = *((u64 *)(tp->trace_id + 8));
    *((u64 *)owner->span_id) = *((u64 *)tp->span_id);
}

static __always_inline u8 go_trace_owner_is_live(const go_trace_owner_t *owner,
                                                 u64 pid,
                                                 u64 generation) {
    go_process_addr_key_t owner_key = {
        .pid = pid,
        .generation = generation,
        .addr = owner->span_addr,
    };
    otel_span_t *span = bpf_map_lookup_elem(&active_spans, &owner_key);
    return span && go_trace_owner_matches(owner, &span->tp);
}

static __always_inline void go_trace_lease_key_from_tp(go_trace_lease_key_t *key,
                                                       u64 pid,
                                                       u64 generation,
                                                       const tp_info_t *tp) {
    key->pid = pid;
    key->generation = generation;
    *((u64 *)key->trace_id) = *((u64 *)tp->trace_id);
    *((u64 *)(key->trace_id + 8)) = *((u64 *)(tp->trace_id + 8));
    *((u64 *)key->span_id) = *((u64 *)tp->span_id);
}

static __always_inline u8 go_trace_generic_is_live(const tp_info_t *tp,
                                                   u64 pid,
                                                   u64 generation,
                                                   go_trace_lease_key_t *lease_key) {
    go_trace_lease_key_from_tp(lease_key, pid, generation, tp);
    return bpf_map_lookup_elem(&go_trace_leases, lease_key) != 0;
}

static __always_inline u8 go_process_addr_keys_match(const go_process_addr_key_t *left,
                                                     const go_process_addr_key_t *right) {
    return left->pid == right->pid && left->generation == right->generation &&
           left->addr == right->addr;
}

static __always_inline u8 try_claim_go_trace_state(const go_process_addr_key_t *state_key) {
    const u8 claimed = 1;
    return bpf_map_update_elem(&go_trace_owner_claims, state_key, &claimed, BPF_NOEXIST) == 0;
}

static __always_inline u8 consume_go_trace_state_reset(const go_process_addr_key_t *state_key) {
    if (!bpf_map_lookup_elem(&go_trace_state_resets, state_key)) {
        return 0;
    }

    bpf_map_delete_elem(&go_trace_map, state_key);
    bpf_map_delete_elem(&go_trace_state_resets, state_key);
    return 1;
}

static __always_inline u8 release_go_trace_state(const go_process_addr_key_t *state_key) {
    const u8 reset = consume_go_trace_state_reset(state_key);
    if (bpf_map_delete_elem(&go_trace_owner_claims, state_key) != 0) {
        // Keep failing closed if the exact claim could not be released.
        return 1;
    }

    // Close the window between consuming the reset and releasing the claim.
    // A resetter that lost its retry race leaves a level-triggered marker.
    if (bpf_map_lookup_elem(&go_trace_state_resets, state_key)) {
        if (!try_claim_go_trace_state(state_key)) {
            return 1;
        }
        consume_go_trace_state_reset(state_key);
        if (bpf_map_delete_elem(&go_trace_owner_claims, state_key) != 0) {
            return 1;
        }
        return 1;
    }

    return reset;
}

static __always_inline u8 claim_go_trace_state(const go_process_addr_key_t *state_key) {
    if (!try_claim_go_trace_state(state_key)) {
        return 0;
    }

    // A reset published before this claim is terminal. Consume it, release the
    // claim, and force the caller to retry instead of creating stale state.
    if (bpf_map_lookup_elem(&go_trace_state_resets, state_key)) {
        consume_go_trace_state_reset(state_key);
        release_go_trace_state(state_key);
        return 0;
    }

    return 1;
}

static __always_inline long delete_go_trace_state(const go_addr_key_t *goroutine_key) {
    if (!goroutine_key) {
        return -1;
    }

    go_process_addr_key_t state_key = {};
    if (!go_process_addr_key_from_go_addr(&state_key, goroutine_key)) {
        return -1;
    }

    if (try_claim_go_trace_state(&state_key)) {
        const long result = bpf_map_delete_elem(&go_trace_map, &state_key);
        return release_go_trace_state(&state_key) ? -1 : result;
    }

    // Publish the terminal condition before retrying the claim. The live
    // claimant observes this marker during release and removes its state.
    const u8 reset = 1;
    if (bpf_map_update_elem(&go_trace_state_resets, &state_key, &reset, BPF_ANY) != 0) {
        return -1;
    }

    if (try_claim_go_trace_state(&state_key)) {
        release_go_trace_state(&state_key);
    }
    return 0;
}

static __always_inline go_trace_state_t *
get_or_create_go_trace_state(const go_process_addr_key_t *state_key,
                             go_trace_state_t *state_scratch) {
    go_trace_state_t *state = bpf_map_lookup_elem(&go_trace_map, state_key);
    if (state) {
        return state;
    }

    if (!state_scratch) {
        return 0;
    }
    __builtin_memset(state_scratch, 0, sizeof(*state_scratch));

    bpf_map_update_elem(&go_trace_map, state_key, state_scratch, BPF_NOEXIST);
    return bpf_map_lookup_elem(&go_trace_map, state_key);
}

static __always_inline long update_go_trace_state(const go_process_addr_key_t *state_key,
                                                  const go_trace_state_t *state) {
    return bpf_map_update_elem(&go_trace_map, state_key, state, k_go_trace_state_update_existing);
}

static __always_inline long poison_go_trace_claimed(const go_process_addr_key_t *state_key) {
    go_trace_state_t *state_scratch = go_trace_state_mem();
    if (!state_scratch) {
        return -1;
    }

    go_trace_state_t *state = get_or_create_go_trace_state(state_key, state_scratch);
    if (!state) {
        return -1;
    }
    __builtin_memcpy(state_scratch, state, sizeof(*state_scratch));
    state_scratch->poisoned = 1;
    return update_go_trace_state(state_key, state_scratch);
}

static __always_inline long poison_go_trace(const go_addr_key_t *g_key) {
    if (!g_key) {
        return -1;
    }

    go_process_addr_key_t state_key = {};
    if (!go_process_addr_key_from_go_addr(&state_key, g_key) || !claim_go_trace_state(&state_key)) {
        return -1;
    }

    const long result = poison_go_trace_claimed(&state_key);
    return release_go_trace_state(&state_key) ? -1 : result;
}

static __noinline __maybe_unused long poison_and_revoke_go_trace(const go_addr_key_t *g_key) {
    if (!g_key) {
        return -1;
    }

    go_process_addr_key_t state_key = {};
    if (!go_process_addr_key_from_go_addr(&state_key, g_key) || !claim_go_trace_state(&state_key)) {
        return -1;
    }

    go_trace_state_t *state_scratch = go_trace_state_mem();
    if (!state_scratch) {
        release_go_trace_state(&state_key);
        return -1;
    }
    go_trace_state_t *state = get_or_create_go_trace_state(&state_key, state_scratch);
    if (!state) {
        release_go_trace_state(&state_key);
        return -1;
    }
    __builtin_memcpy(state_scratch, state, sizeof(*state_scratch));

    go_trace_lease_key_t lease_key = {};
    const u8 had_generic = state_scratch->has_generic;
    if (had_generic) {
        go_trace_lease_key_from_tp(
            &lease_key, state_key.pid, state_key.generation, &state_scratch->generic_tp);
        state_scratch->has_generic = 0;
    }
    state_scratch->poisoned = 1;

    long result = update_go_trace_state(&state_key, state_scratch);
    if (result == 0 && had_generic) {
        result = bpf_map_delete_elem(&go_trace_leases, &lease_key);
    }
    return release_go_trace_state(&state_key) ? -1 : result;
}

static __always_inline s8
resolve_current_go_trace_claimed(go_trace_parent_t *resolved,
                                 const go_process_addr_key_t *state_key,
                                 go_trace_resolve_scratch_t *resolve_scratch) {
    go_trace_state_t *state_scratch = go_trace_state_mem();
    if (!state_scratch) {
        return k_go_trace_parent_error;
    }

    go_trace_state_t *state = bpf_map_lookup_elem(&go_trace_map, state_key);
    if (!state) {
        return k_go_trace_parent_not_found;
    }
    __builtin_memcpy(state_scratch, state, sizeof(*state_scratch));

    __builtin_memset(resolved, 0, sizeof(*resolved));
    if (state_scratch->poisoned) {
        return k_go_trace_parent_error;
    }

    if (state_scratch->has_owner) {
        resolve_scratch->owner_key.pid = state_key->pid;
        resolve_scratch->owner_key.generation = state_key->generation;
        resolve_scratch->owner_key.addr = state_scratch->owner.span_addr;
        otel_span_t *span = bpf_map_lookup_elem(&active_spans, &resolve_scratch->owner_key);
        if (span) {
            __builtin_memcpy(&resolved->tp, &span->tp, sizeof(resolved->tp));
            if (go_trace_owner_matches(&state_scratch->owner, &resolved->tp)) {
                go_trace_state_t *current = bpf_map_lookup_elem(&go_trace_map, state_key);
                if (current && current->has_owner == state_scratch->has_owner &&
                    current->has_generic == state_scratch->has_generic &&
                    current->poisoned == state_scratch->poisoned &&
                    go_trace_owners_match(&current->owner, &state_scratch->owner)) {
                    return k_go_trace_parent_found;
                }
            }
        }
    }

    // The owner lookup above may have caused LRU reuse. Snapshot the state
    // again before considering the generic trace parent.
    state = bpf_map_lookup_elem(&go_trace_map, state_key);
    if (!state) {
        return k_go_trace_parent_not_found;
    }
    __builtin_memcpy(state_scratch, state, sizeof(*state_scratch));
    if (state_scratch->poisoned) {
        return k_go_trace_parent_error;
    }

    if (state_scratch->has_generic && go_trace_generic_is_live(&state_scratch->generic_tp,
                                                               state_key->pid,
                                                               state_key->generation,
                                                               &resolve_scratch->lease_key)) {
        go_trace_state_t *current = bpf_map_lookup_elem(&go_trace_map, state_key);
        if (!current || current->has_owner != state_scratch->has_owner ||
            current->has_generic != state_scratch->has_generic ||
            current->poisoned != state_scratch->poisoned ||
            !go_trace_ids_match(current->generic_tp.trace_id,
                                current->generic_tp.span_id,
                                &state_scratch->generic_tp)) {
            return k_go_trace_parent_not_found;
        }
        __builtin_memcpy(&resolved->tp, &state_scratch->generic_tp, sizeof(resolved->tp));
        return k_go_trace_parent_found;
    }

    return k_go_trace_parent_not_found;
}

static __noinline s8 resolve_current_go_trace(go_trace_parent_t *resolved,
                                              go_trace_resolve_scratch_t *resolve_scratch) {
    if (!resolved || !resolve_scratch || !claim_go_trace_state(&resolve_scratch->state_key)) {
        return k_go_trace_parent_error;
    }

    const s8 result =
        resolve_current_go_trace_claimed(resolved, &resolve_scratch->state_key, resolve_scratch);
    return release_go_trace_state(&resolve_scratch->state_key) ? k_go_trace_parent_error : result;
}

static __always_inline long
publish_go_trace_owner_claimed(const go_process_addr_key_t *state_key,
                               const go_trace_owner_t *published_owner) {
    go_trace_state_t *state_scratch = go_trace_state_mem();
    if (!state_scratch) {
        return -1;
    }
    go_trace_state_t *state = get_or_create_go_trace_state(state_key, state_scratch);
    if (!state) {
        return -1;
    }
    __builtin_memcpy(state_scratch, state, sizeof(*state_scratch));

    go_trace_owner_link_scratch_t *link_scratch = go_trace_owner_link_scratch_mem();
    if (!link_scratch) {
        state_scratch->poisoned = 1;
        update_go_trace_state(state_key, state_scratch);
        return -1;
    }

    __builtin_memset(&link_scratch->current, 0, sizeof(link_scratch->current));
    link_scratch->current.goroutine = *state_key;
    link_scratch->current.owner = *published_owner;
    if (state_scratch->has_owner) {
        if (go_trace_owners_match(&state_scratch->owner, published_owner)) {
            state_scratch->poisoned = 0;
            return update_go_trace_state(state_key, state_scratch);
        }
        if (go_trace_owner_is_live(&state_scratch->owner, state_key->pid, state_key->generation)) {
            link_scratch->current.previous = state_scratch->owner;
            link_scratch->current.has_previous = 1;
        }
    }

    go_process_addr_key_t owner_key = {
        .pid = state_key->pid,
        .generation = state_key->generation,
        .addr = published_owner->span_addr,
    };
    if (bpf_map_update_elem(&go_trace_owner_links, &owner_key, &link_scratch->current, BPF_ANY) !=
        0) {
        state_scratch->poisoned = 1;
        update_go_trace_state(state_key, state_scratch);
        return -1;
    }

    state_scratch->owner = *published_owner;
    state_scratch->has_owner = 1;
    state_scratch->poisoned = 0;
    return update_go_trace_state(state_key, state_scratch);
}

static __noinline __maybe_unused long
publish_go_trace_owner(const go_addr_key_t *g_key, const tp_info_t *tp, u64 owner_span) {
    if (!g_key || !tp || !owner_span) {
        return -1;
    }

    // tp can point into active_spans, an LRU map. Snapshot every field needed
    // by this transition before the first helper can invalidate that pointer.
    go_trace_owner_t published_owner = {};
    go_trace_owner_from_tp(&published_owner, tp, owner_span);

    go_process_addr_key_t state_key = {};
    if (!go_process_addr_key_from_go_addr(&state_key, g_key) || !claim_go_trace_state(&state_key)) {
        return -1;
    }

    const long result = publish_go_trace_owner_claimed(&state_key, &published_owner);
    return release_go_trace_state(&state_key) ? -1 : result;
}

static __always_inline void
retire_go_trace_owner_claimed(const go_process_addr_key_t *generated_owner_key,
                              const go_process_addr_key_t *claimed_state_key,
                              const go_trace_owner_t *retiring_owner) {
    go_trace_owner_link_scratch_t *link_scratch = go_trace_owner_link_scratch_mem();
    if (!link_scratch) {
        return;
    }

    go_trace_owner_link_t *stored_link =
        bpf_map_lookup_elem(&go_trace_owner_links, generated_owner_key);
    if (!stored_link) {
        return;
    }
    __builtin_memcpy(&link_scratch->current, stored_link, sizeof(link_scratch->current));
    if (!go_process_addr_keys_match(&link_scratch->current.goroutine, claimed_state_key) ||
        !go_trace_owners_match(&link_scratch->current.owner, retiring_owner)) {
        return;
    }

    go_trace_state_t *state_scratch = go_trace_state_mem();
    if (!state_scratch) {
        return;
    }
    go_trace_state_t *state = bpf_map_lookup_elem(&go_trace_map, claimed_state_key);
    if (!state || !state->has_owner) {
        return;
    }
    __builtin_memcpy(state_scratch, state, sizeof(*state_scratch));
    if (!state_scratch->has_owner ||
        !go_trace_owners_match(&state_scratch->owner, retiring_owner)) {
        return;
    }

    if (bpf_map_delete_elem(&go_trace_owner_links, generated_owner_key) != 0) {
        return;
    }

    state_scratch->has_owner = 0;
#pragma clang loop unroll(disable)
    for (u8 depth = 0; depth < k_go_owner_restore_depth; depth++) {
        if (!link_scratch->current.has_previous) {
            break;
        }
        if (go_trace_owner_is_live(&link_scratch->current.previous,
                                   claimed_state_key->pid,
                                   claimed_state_key->generation)) {
            state_scratch->owner = link_scratch->current.previous;
            state_scratch->has_owner = 1;
            break;
        }

        go_process_addr_key_t previous_key = {
            .pid = claimed_state_key->pid,
            .generation = claimed_state_key->generation,
            .addr = link_scratch->current.previous.span_addr,
        };
        go_trace_owner_link_t *stored_previous =
            bpf_map_lookup_elem(&go_trace_owner_links, &previous_key);
        if (!stored_previous) {
            break;
        }
        __builtin_memcpy(&link_scratch->previous, stored_previous, sizeof(link_scratch->previous));
        if (!go_trace_owners_match(&link_scratch->previous.owner,
                                   &link_scratch->current.previous)) {
            break;
        }
        bpf_map_delete_elem(&go_trace_owner_links, &previous_key);
        link_scratch->current = link_scratch->previous;
    }

    // The bounded traversal may end immediately after loading the next
    // candidate. Preserve that final live owner without following another link.
    if (!state_scratch->has_owner && link_scratch->current.has_previous &&
        go_trace_owner_is_live(&link_scratch->current.previous,
                               claimed_state_key->pid,
                               claimed_state_key->generation)) {
        state_scratch->owner = link_scratch->current.previous;
        state_scratch->has_owner = 1;
    }

    update_go_trace_state(claimed_state_key, state_scratch);
}

static __noinline __maybe_unused void retire_go_trace_owner(const go_addr_key_t *owner_key,
                                                            const tp_info_t *tp) {
    if (!owner_key || !tp) {
        return;
    }

    // Both inputs can refer to LRU values. Snapshot the retirement identity
    // before generation lookup or any map helper can reuse those values.
    const go_addr_key_t owner_key_snapshot = *owner_key;
    go_trace_owner_t retiring_owner = {};
    go_trace_owner_from_tp(&retiring_owner, tp, owner_key_snapshot.addr);

    go_process_addr_key_t generated_owner_key = {};
    if (!go_process_addr_key_from_go_addr(&generated_owner_key, &owner_key_snapshot)) {
        return;
    }

    go_trace_owner_link_scratch_t *link_scratch = go_trace_owner_link_scratch_mem();
    if (!link_scratch) {
        return;
    }
    go_trace_owner_link_t *stored_link =
        bpf_map_lookup_elem(&go_trace_owner_links, &generated_owner_key);
    if (!stored_link) {
        return;
    }
    __builtin_memcpy(&link_scratch->current, stored_link, sizeof(link_scratch->current));
    if (link_scratch->current.goroutine.pid != generated_owner_key.pid ||
        link_scratch->current.goroutine.generation != generated_owner_key.generation ||
        !go_trace_owners_match(&link_scratch->current.owner, &retiring_owner)) {
        return;
    }

    const go_process_addr_key_t claimed_state_key = link_scratch->current.goroutine;
    if (!claim_go_trace_state(&claimed_state_key)) {
        return;
    }

    retire_go_trace_owner_claimed(&generated_owner_key, &claimed_state_key, &retiring_owner);
    release_go_trace_state(&claimed_state_key);
}

static __always_inline long push_go_trace(const go_addr_key_t *g_key, const tp_info_t *tp) {
    if (!g_key || !tp) {
        return -1;
    }

    // Callers may pass an LRU-backed trace parent. Copy it before generation
    // lookup and claim helpers can invalidate the source pointer.
    const tp_info_t tp_snapshot = *tp;

    go_process_addr_key_t state_key = {};
    if (!go_process_addr_key_from_go_addr(&state_key, g_key) || !claim_go_trace_state(&state_key)) {
        return -1;
    }

    go_trace_lease_key_t lease_key = {};
    go_trace_lease_key_from_tp(&lease_key, state_key.pid, state_key.generation, &tp_snapshot);
    const u8 active = 1;
    if (bpf_map_update_elem(&go_trace_leases, &lease_key, &active, BPF_ANY) != 0) {
        poison_go_trace_claimed(&state_key);
        release_go_trace_state(&state_key);
        return -1;
    }

    go_trace_state_t *state_scratch = go_trace_state_mem();
    if (!state_scratch) {
        bpf_map_delete_elem(&go_trace_leases, &lease_key);
        release_go_trace_state(&state_key);
        return -1;
    }
    go_trace_state_t *state = get_or_create_go_trace_state(&state_key, state_scratch);
    if (!state) {
        bpf_map_delete_elem(&go_trace_leases, &lease_key);
        poison_go_trace_claimed(&state_key);
        release_go_trace_state(&state_key);
        return -1;
    }
    __builtin_memcpy(state_scratch, state, sizeof(*state_scratch));

    if (state_scratch->has_generic && !go_trace_ids_match(state_scratch->generic_tp.trace_id,
                                                          state_scratch->generic_tp.span_id,
                                                          &tp_snapshot)) {
        go_trace_lease_key_t previous_key = {};
        go_trace_lease_key_from_tp(
            &previous_key, state_key.pid, state_key.generation, &state_scratch->generic_tp);
        bpf_map_delete_elem(&go_trace_leases, &previous_key);
    }

    __builtin_memcpy(&state_scratch->generic_tp, &tp_snapshot, sizeof(tp_snapshot));
    state_scratch->has_generic = 1;
    state_scratch->poisoned = 0;
    if (update_go_trace_state(&state_key, state_scratch) != 0) {
        bpf_map_delete_elem(&go_trace_leases, &lease_key);
        release_go_trace_state(&state_key);
        return -1;
    }

    if (release_go_trace_state(&state_key)) {
        bpf_map_delete_elem(&go_trace_leases, &lease_key);
        return -1;
    }
    return 0;
}

static __always_inline long pop_go_trace(const go_addr_key_t *g_key, const tp_info_t *tp) {
    if (!g_key || !tp) {
        return -1;
    }

    // Snapshot all LRU-backed inputs before generation lookup can reuse them.
    go_trace_lease_key_t lease_key = {};
    go_trace_lease_key_from_tp(&lease_key, g_key->pid, 0, tp);
    const u64 generation = go_process_generation(lease_key.pid);
    if (!generation) {
        return -1;
    }
    lease_key.generation = generation;
    return bpf_map_delete_elem(&go_trace_leases, &lease_key);
}

static __always_inline s8 resolve_go_trace_in_chain(go_trace_parent_t *resolved,
                                                    go_addr_key_t *current,
                                                    u64 *found_addr) {
    if (!current) {
        return k_go_trace_parent_not_found;
    }

    go_addr_key_t parent = *current;
    const u64 generation = go_process_generation(parent.pid);
    if (!generation) {
        return k_go_trace_parent_not_found;
    }

    go_trace_resolve_scratch_t *resolve_scratch = go_trace_resolve_scratch_mem();
    if (!resolve_scratch) {
        return k_go_trace_parent_error;
    }

    int attempts = 0;
    do {
        if (!go_process_addr_key_from_generation(
                &resolve_scratch->state_key, &parent, generation)) {
            return k_go_trace_parent_not_found;
        }
        const s8 result = resolve_current_go_trace(resolved, resolve_scratch);
        if (result == k_go_trace_parent_error) {
            return result;
        }
        if (result == k_go_trace_parent_not_found) {
            goroutine_metadata *g_metadata =
                (goroutine_metadata *)bpf_map_lookup_elem(&ongoing_goroutines, &parent);
            if (g_metadata && g_metadata->generation == generation) {
                const go_addr_key_t next_parent = g_metadata->parent;
                if (next_parent.addr == parent.addr) {
                    break;
                }
                parent = next_parent;
            } else {
                break;
            }
        } else {
            if (found_addr) {
                *found_addr = parent.addr;
            }
            bpf_dbg_printk("Found parent, r_addr=%lx", parent.addr);
            return k_go_trace_parent_found;
        }

        attempts++;
        // We loop far back because some clients, e.g. Kafka Franz-Go really nest the
        // client calls.
    } while (attempts < 6); // Up to 6 levels of goroutine nesting allowed

    return k_go_trace_parent_not_found;
}

static __always_inline u64 find_parent_goroutine(go_addr_key_t *current) {
    go_trace_parent_t resolved = {};
    u64 found_addr = 0;
    const s8 result = resolve_go_trace_in_chain(&resolved, current, &found_addr);
    if (result == k_go_trace_parent_error) {
        return k_go_parent_error;
    }
    return result == k_go_trace_parent_found ? found_addr : 0;
}

static __always_inline u64 find_parent_goroutine_in_chain(go_addr_key_t *current) {
    if (!current) {
        return 0;
    }

    // Let's find the parent scope
    goroutine_metadata *g_metadata =
        (goroutine_metadata *)bpf_map_lookup_elem(&ongoing_goroutines, current);
    const u64 generation = go_process_generation(current->pid);
    if (g_metadata && generation && g_metadata->generation == generation) {
        // Lookup now to see if the parent was a request
        return g_metadata->parent.addr;
    }

    return 0;
}

static __always_inline u8 decode_go_traceparent(const unsigned char *buf,
                                                unsigned char *trace_id,
                                                unsigned char *span_id,
                                                unsigned char *flags) {
    if (!valid_traceparent_value(buf)) {
        return 0;
    }

    const unsigned char *t_id = buf + 2 + 1; // strlen(ver) + strlen("-")
    const unsigned char *s_id =
        buf + 2 + 1 + 32 + 1; // strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-")
    const unsigned char *f_id =
        buf + 2 + 1 + 32 + 1 + 16 +
        1; // strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-") + strlen(span_id) + strlen("-")

    decode_hex(trace_id, t_id, TRACE_ID_CHAR_LEN);
    decode_hex(span_id, s_id, SPAN_ID_CHAR_LEN);
    decode_hex(flags, f_id, FLAGS_CHAR_LEN);
    *flags = traceparent_flags_for_version(buf, *flags);
    return 1;
}

static __always_inline void tp_from_parent(tp_info_t *tp, tp_info_t *parent) {
    *((u64 *)tp->trace_id) = *((u64 *)parent->trace_id);
    *((u64 *)(tp->trace_id + 8)) = *((u64 *)(parent->trace_id + 8));
    *((u64 *)tp->parent_id) = *((u64 *)parent->span_id);
    inherit_parent_sampling_state(tp, parent);
}

static __always_inline void tp_clone(tp_info_t *dest, tp_info_t *src) {
    *((u64 *)dest->trace_id) = *((u64 *)src->trace_id);
    *((u64 *)(dest->trace_id + 8)) = *((u64 *)(src->trace_id + 8));
    *((u64 *)dest->span_id) = *((u64 *)src->span_id);
    *((u64 *)dest->parent_id) = *((u64 *)src->parent_id);
    copy_sampling_state(dest, src);
}

static __always_inline void discard_server_parent_candidates(const go_addr_key_t *goroutine_key) {
    go_server_connection_t *state = go_server_connection_lookup_current(goroutine_key);
    if (!state) {
        return;
    }

    connection_info_t conn = state->conn;
    sort_connection_info(&conn);
    bpf_map_delete_elem(&incoming_trace_map, &conn);
    delete_trace_info_for_connection(&conn, TRACE_TYPE_CLIENT);
}

static __always_inline void
server_trace_parent(void *goroutine_addr, tp_info_t *tp, tp_info_t *found_tp, u8 force_root) {
    tp->flags = k_flag_sampled;
    tp->ts = bpf_ktime_get_ns();
    u8 found_parent = 0;
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    if (force_root) {
        discard_server_parent_candidates(&g_key);
    }
    if (found_tp && !force_root) {
        bpf_dbg_printk("Decoded from existing traceparent");
        __builtin_memcpy(tp, found_tp, sizeof(tp_info_t));
        tp->sampling_decision = k_sampling_decision_pending;
        found_parent = 1;
    } else {
        go_server_connection_t *state =
            force_root ? NULL : go_server_connection_lookup_current(&g_key);
        u8 found_info = 0;

        if (state) {
            connection_info_t conn = state->conn;
            // Must sort here, Go connection info retains the original ordering.
            sort_connection_info(&conn);

            // First we look-up if we have information passed down to us from
            // TCP/IP context propagation.
            tp_info_pid_t *existing_tp = bpf_map_lookup_elem(&incoming_trace_map, &conn);
            if (existing_tp) {
                bpf_dbg_printk("Found incoming (TCP) tp for server request");
                found_info = 1;
                found_parent = 1;
                tp_from_parent(tp, &existing_tp->tp);
                bpf_map_delete_elem(&incoming_trace_map, &conn);
            } else {
                // If not, we then look up the information in the black-box context map - same node.
                bpf_dbg_printk("Looking up traceparent for connection info");
                tp_info_pid_t *tp_p = trace_info_for_connection(&conn, TRACE_TYPE_CLIENT);
                if (!disable_black_box_cp && tp_p) {
                    if (correlated_request_with_current(tp_p)) {
                        bpf_dbg_printk("Found traceparent from trace map, another process.");
                        found_info = 1;
                        found_parent = 1;
                        tp_from_parent(tp, &tp_p->tp);
                    }
                }
            }
        }

        if (!found_info) {
            bpf_dbg_printk("No traceparent in headers, generating");
            new_trace_id(tp);
            *((u64 *)tp->parent_id) = 0;
        }
    }

    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
    apply_sampling_decision(tp, found_parent, found_parent);
    // found_tp memcpy clobbered ts; reset before go_trace_map store
    tp->ts = bpf_ktime_get_ns();
    push_go_trace(&g_key, tp);

    unsigned char tp_buf[TP_MAX_VAL_LENGTH];
    make_tp_string(tp_buf, tp);
    bpf_dbg_printk("tp_buf=[%s]", tp_buf);
}

static __always_inline s8 tp_info_from_parent_go(go_addr_key_t *g_key,
                                                 u64 *parent_found,
                                                 tp_info_t *tp) {
    go_trace_parent_t resolved = {};
    u64 parent_id = 0;
    const s8 result = resolve_go_trace_in_chain(&resolved, g_key, &parent_id);
    if (result == k_go_trace_parent_found) {
        __builtin_memcpy(tp, &resolved.tp, sizeof(*tp));
    } else {
        return result;
    }

    bpf_dbg_printk("Found parent request, tp=%llx", tp);
    if (parent_found) {
        *parent_found = parent_id;
    }

    return k_go_trace_parent_found;
}

static __always_inline void update_tp_parent_go(go_addr_key_t *gp_key, const tp_info_t *tp) {
    push_go_trace(gp_key, tp);
}

static __always_inline u8 client_trace_parent(void *goroutine_addr, tp_info_t *tp_i) {
    u8 found_trace_id = 0;

    tp_i->flags = k_flag_sampled;
    reset_sampling_decision(tp_i);
    __builtin_memset(tp_i->parent_id, 0, sizeof(tp_i->parent_id));
    // We set the time of the current client trace parent
    tp_i->ts = bpf_ktime_get_ns();

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    // We first check for Cloud web databases (like snowflake), which wrap HTTP calls with SQL
    // statements.
    if (!found_trace_id) {
        sql_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
        if (invocation) {
            tp_from_parent(tp_i, &invocation->tp);
            found_trace_id = 1;
        }
    }

    if (!found_trace_id) {
        tp_info_t tp = {};
        const s8 parent_result = tp_info_from_parent_go(&g_key, 0, &tp);
        if (parent_result == k_go_trace_parent_error) {
            new_trace_id(tp_i);
            urand_bytes(tp_i->span_id, SPAN_ID_SIZE_BYTES);
            __builtin_memset(tp_i->parent_id, 0, sizeof(tp_i->parent_id));
            apply_fail_closed_sampler_result(tp_i);
            return 0;
        }
        if (parent_result == k_go_trace_parent_found) {
            if (should_be_in_same_transaction(&tp, tp_i)) {
                tp_from_parent(tp_i, &tp);
                found_trace_id = 1;
            } else {
                bpf_dbg_printk("Parent and child are too far apart, ignoring parent trace_id");
            }
        }

        if (!found_trace_id) {
            new_trace_id(tp_i);
        }

        urand_bytes(tp_i->span_id, SPAN_ID_SIZE_BYTES);
    }

    apply_sampling_decision(tp_i, found_trace_id, 0);
    return found_trace_id;
}

static __always_inline void read_ip_and_port(void *src, u8 *dst_ip, u16 *dst_port) {
    s64 addr_len = 0;
    void *addr_ip = 0;
    off_table_t *ot = get_offsets_table();

    bpf_probe_read_user(dst_port,
                        sizeof(u16),
                        (void *)(src + go_offset_of(ot, (go_offset){.v = _tcp_addr_port_ptr_pos})));
    bpf_probe_read_user(&addr_ip,
                        sizeof(addr_ip),
                        (void *)(src + go_offset_of(ot, (go_offset){.v = _tcp_addr_ip_ptr_pos})));
    if (addr_ip) {
        bpf_probe_read_user(
            &addr_len,
            sizeof(addr_len),
            (void *)(src + go_offset_of(ot, (go_offset){.v = _tcp_addr_ip_ptr_pos}) + 8));
        if (addr_len == 4) {
            __builtin_memcpy(dst_ip, ip4ip6_prefix, sizeof(ip4ip6_prefix));
            bpf_probe_read_user(dst_ip + sizeof(ip4ip6_prefix), 4, addr_ip);
        } else if (addr_len == 16) {
            bpf_probe_read_user(dst_ip, 16, addr_ip);
        }
    }
}

static __always_inline u8 get_conn_info_from_fd(void *fd_ptr,
                                                connection_info_t *info,
                                                const bool mark_handled) {
    if (fd_ptr) {
        void *laddr_ptr = 0;
        void *raddr_ptr = 0;
        off_table_t *ot = get_offsets_table();
        const u64 fd_laddr_pos = go_offset_of(ot, (go_offset){.v = _fd_laddr_pos});

        bpf_probe_read_user(
            &laddr_ptr, sizeof(laddr_ptr), (void *)(fd_ptr + fd_laddr_pos + 8)); // find laddr
        bpf_probe_read_user(
            &raddr_ptr,
            sizeof(raddr_ptr),
            (void *)(fd_ptr + go_offset_of(ot, (go_offset){.v = _fd_raddr_pos}) + 8)); // find raddr

        bpf_dbg_printk("laddr_field_ptr=%llx, laddr_ptr=%llx, raddr_ptr=%llx",
                       fd_ptr + fd_laddr_pos + 8, //laddr_field_ptr
                       laddr_ptr,
                       raddr_ptr);
        if (laddr_ptr && raddr_ptr) {

            // read local
            read_ip_and_port(laddr_ptr, info->s_addr, &info->s_port);

            // read remote
            read_ip_and_port(raddr_ptr, info->d_addr, &info->d_port);

            //dbg_print_http_connection_info(info);

            // IMPORTANT: Unlike kprobes, where we track the sorted connection info
            // in Go we keep the original connection info order, since we only need it
            // sorted when we make server requests or when we populate the trace_map for
            // black box context propagation.

            if (mark_handled) {
                store_go_handled_connection_info(info);
            }

            return 1;
        }
    }

    return 0;
}

static __always_inline void *fd_ptr_from_conn(void *conn_ptr) {
    if (conn_ptr) {
        void *fd_ptr = 0;
        off_table_t *ot = get_offsets_table();

        bpf_probe_read_user(
            &fd_ptr,
            sizeof(fd_ptr),
            (void *)(conn_ptr + go_offset_of(ot, (go_offset){.v = _conn_fd_pos}))); // find fd

        return fd_ptr;
    }

    return 0;
}

// HTTP black-box context propagation
static __always_inline u8 get_conn_info(void *conn_ptr, connection_info_t *info) {
    if (conn_ptr) {
        void *fd_ptr = fd_ptr_from_conn(conn_ptr);
        bpf_dbg_printk("Found fd, fd_ptr=%llx", fd_ptr);

        if (fd_ptr) {
            return get_conn_info_from_fd(fd_ptr, info, true);
        }
    }

    return 0;
}

static __always_inline void *unwrap_tls_conn_info(void *conn_ptr, void *tls_state) {
    if (conn_ptr && tls_state) {
        void *c_ptr = 0;
        bpf_probe_read(&c_ptr, sizeof(c_ptr), conn_ptr); // unwrap conn

        bpf_dbg_printk("unwrapped conn, c_ptr=%llx", c_ptr);

        if (c_ptr) {
            return c_ptr + 8;
        }
    }

    return conn_ptr;
}

enum go_meta_headers_traceparent_result : u8 {
    k_go_meta_headers_traceparent_unknown = 0,
    k_go_meta_headers_traceparent_absent = 1,
    k_go_meta_headers_traceparent_found = 2,
    k_go_meta_headers_traceparent_present = 3,
};

static __always_inline enum go_meta_headers_traceparent_result
process_meta_frame_headers_classified(void *frame, tp_info_t *tp) {
    if (!frame || !tp) {
        return k_go_meta_headers_traceparent_unknown;
    }

    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return k_go_meta_headers_traceparent_unknown;
    }

    void *fields = 0;
    const u64 fields_off = go_offset_of(ot, (go_offset){.v = _meta_headers_frame_fields_ptr_pos});
    u64 fields_len = 0;
    if (bpf_probe_read(&fields, sizeof(fields), (void *)(frame + fields_off)) ||
        bpf_probe_read(&fields_len, sizeof(fields_len), (void *)(frame + fields_off + 8))) {
        return k_go_meta_headers_traceparent_unknown;
    }
    bpf_dbg_printk("fields=%llx, fields_len=%d", fields, fields_len);
    if (fields_len > k_go_meta_headers_max_fields) {
        return k_go_meta_headers_traceparent_unknown;
    }
    if (fields_len == 0) {
        return k_go_meta_headers_traceparent_absent;
    }
    if (!fields) {
        return k_go_meta_headers_traceparent_unknown;
    }

    void *traceparent_value = 0;
    u8 saw_traceparent = 0;
    unsigned char temp[W3C_VAL_LENGTH] = {};
    for (u8 i = 0; i < k_go_meta_headers_max_fields; i++) {
        if (i >= fields_len) {
            break;
        }
        void *field_ptr = fields + (i * sizeof(grpc_header_field_t));
        grpc_header_field_t field = {};
        if (bpf_probe_read(&field, sizeof(field), field_ptr)) {
            return k_go_meta_headers_traceparent_unknown;
        }
        if (field.key_len != W3C_KEY_LENGTH) {
            continue;
        }
        if (bpf_probe_read(temp, W3C_KEY_LENGTH, field.key_ptr)) {
            return k_go_meta_headers_traceparent_unknown;
        }
        if (!stricmp((const char *)temp, "traceparent", W3C_KEY_LENGTH)) {
            continue;
        }
        if (saw_traceparent || field.val_len != W3C_VAL_LENGTH) {
            return k_go_meta_headers_traceparent_present;
        }
        saw_traceparent = 1;
        traceparent_value = field.val_ptr;
    }
    if (!saw_traceparent) {
        return k_go_meta_headers_traceparent_absent;
    }
    if (bpf_probe_read(temp, W3C_VAL_LENGTH, traceparent_value)) {
        return k_go_meta_headers_traceparent_present;
    }
    tp_info_t decoded = {};
    if (!decode_go_traceparent(temp, decoded.trace_id, decoded.parent_id, &decoded.flags)) {
        return k_go_meta_headers_traceparent_present;
    }
    *tp = decoded;
    return k_go_meta_headers_traceparent_found;
}

static __always_inline void process_meta_frame_headers(void *frame, tp_info_t *tp) {
    process_meta_frame_headers_classified(frame, tp);
}

// Reads the StreamID of the HeadersFrameParam passed to
// golang.org/x/net/http2.(*Framer).WriteHeaders.
//
// Whether that struct is register- or stack-assigned depends on the Go internal
// ABI's register budget. Counting the receiver, the call needs 11 integer
// argument registers. amd64 offers 9, so from x/net/http2 v0.45.0 on — when the
// struct grew past the budget — Go assigns it entirely to the stack, with
// StreamID as its first field one word above SP (the CALL instruction pushed the
// return address). arm64 offers 16 (R0-R15), so the struct still fits in
// registers there and StreamID stays in R1.
// https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md
static __always_inline u64 golang_stream_id(struct pt_regs *ctx, off_table_t *ot) {
#ifdef __TARGET_ARCH_x86
    const u64 on_stack = go_offset_of(ot, (go_offset){.v = _http2_zero_forty_five_zero});

    if (on_stack) {
        const void *sp = (const void *)PT_REGS_SP(ctx);

        bpf_dbg_printk("sp=%llx", sp);

        // StreamID is a u32; reading it as such avoids depending on the
        // struct's alignment padding.
        u32 stream_id = 0;
        const u8 k_stream_id_offset = 0x8;

        if (bpf_probe_read_user(&stream_id, sizeof(stream_id), sp + k_stream_id_offset) != 0) {
            bpf_dbg_printk("couldn't read stream_id");
            return 0;
        }

        return stream_id;
    }
#endif

    return (u64)GO_PARAM2(ctx);
}
