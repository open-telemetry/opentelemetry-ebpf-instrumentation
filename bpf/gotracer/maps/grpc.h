// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/outgoing_trace_handoff.h>
#include <common/pin_internal.h>

#include <gotracer/maps/outgoing_trace_handoff.h>
#include <gotracer/types/grpc.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, u16);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_request_status SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_client_requests SEC(".maps");

// Serializes replacement and exact conditional deletion of the reusable
// creator-goroutine locator. A live claim must never be evicted.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_addr_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_client_creator_request_claims SEC(".maps");

// Canonical request state is a bounded hint which survives the creator
// goroutine returning from ClientConn.NewStream. Stable stream pointers and
// transport-side copies carry only the incarnation-scoped request ID back to
// this state. Exact outgoing handoff authority remains non-evicting.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, grpc_client_request_id_t);
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_client_request_states SEC(".maps");

struct {
    // This is a safely evictable locator, not request authority. The value is
    // an exact incarnation-scoped request ID and every consumer revalidates it
    // through grpc_client_request_states.
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // pid + stable *clientStream
    __type(value, grpc_client_request_id_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_client_stream_requests SEC(".maps");

// RecvMsg returns only an error, so retain its receiver across the return
// probe. This is staging state, not request authority.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t); // current process + goroutine
    __type(value, go_addr_key_t);             // stable *clientStream key
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_client_recv_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_client_request_sequences SEC(".maps");

#define GRPC_CLIENT_HANDOFF_SLOTS 4

enum {
    k_grpc_client_handoff_poisoned = 1U << 7,
};

typedef struct grpc_client_handoff_slot_key {
    grpc_client_request_id_t request_id;
    u8 slot;
    u8 _pad[7];
} grpc_client_handoff_slot_key_t;

// A logical gRPC request can create more than one transport stream (for
// example, a transparent retry). These bounded, evictable reverse hints make
// exact authority orphaned rather than permanently consuming map capacity
// after a missed terminal hook or process death. On per-request saturation the
// whole request is poisoned and every retained exact authority is retired.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, grpc_client_request_id_t);
    __type(value, u8); // occupied slot bits plus k_grpc_client_handoff_poisoned
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_client_request_handoff_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, grpc_client_handoff_slot_key_t);
    __type(value, go_outgoing_trace_handoff_ref_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS *GRPC_CLIENT_HANDOFF_SLOTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_client_request_handoffs SEC(".maps");

// Claims are held only within one non-NMI probe invocation. They cannot be LRU:
// evicting a live claim would admit two owners for one exact request.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, grpc_client_request_id_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_client_request_handoff_claims SEC(".maps");

// Serializes every mutation of a reusable pid + *clientStream locator. This
// makes exact conditional deletion atomic with respect to replacement.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_addr_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_client_stream_request_claims SEC(".maps");

static __always_inline u8 grpc_client_request_ids_match(const grpc_client_request_id_t *left,
                                                        const grpc_client_request_id_t *right) {
    return left && right && left->process_start_time &&
           left->process_start_time == right->process_start_time &&
           left->sequence == right->sequence && left->cpu == right->cpu &&
           left->creator.pid == right->creator.pid && left->creator.addr == right->creator.addr;
}

static __always_inline u8
grpc_client_request_id_is_current(const grpc_client_request_id_t *request_id) {
    if (!request_id || request_id->creator.pid != (u64)(u32)request_id->creator.pid) {
        return 0;
    }
    return process_incarnation_matches_current_exact((u32)request_id->creator.pid,
                                                     request_id->process_start_time);
}

static __always_inline u8
defer_grpc_client_request_terminal(const grpc_client_request_id_t *request_id, u8 terminal_error) {
    if (!grpc_client_request_id_is_current(request_id)) {
        return 0;
    }
    grpc_client_func_invocation_t *canonical =
        bpf_map_lookup_elem(&grpc_client_request_states, request_id);
    if (!canonical) {
        return 0;
    }
    if (!canonical->terminal) {
        canonical->terminal_error = terminal_error;
        canonical->terminal = 1;
    }
    return 1;
}

// The caller holds request_id's exact claim. Returns true exactly once.
static __always_inline u8
mark_grpc_client_request_terminal_emitted(const grpc_client_request_id_t *request_id) {
    grpc_client_func_invocation_t *canonical =
        bpf_map_lookup_elem(&grpc_client_request_states, request_id);
    if (!canonical || !canonical->terminal || canonical->terminal_emitted) {
        return 0;
    }
    canonical->terminal_emitted = 1;
    return 1;
}

static __always_inline u8 claim_grpc_client_creator_request(const go_addr_key_t *creator_key) {
    const u8 claimed = 1;
    return creator_key &&
           bpf_map_update_elem(
               &grpc_client_creator_request_claims, creator_key, &claimed, BPF_NOEXIST) == 0;
}

static __always_inline void release_grpc_client_creator_request(const go_addr_key_t *creator_key) {
    if (creator_key) {
        bpf_map_delete_elem(&grpc_client_creator_request_claims, creator_key);
    }
}

static __always_inline u8 publish_grpc_client_creator_request(
    const go_addr_key_t *creator_key, const grpc_client_func_invocation_t *invocation) {
    if (!creator_key || !invocation) {
        return 0;
    }
    if (!claim_grpc_client_creator_request(creator_key)) {
        bpf_map_delete_elem(&grpc_client_request_states, &invocation->request_id);
        return 0;
    }
    const u8 published =
        bpf_map_update_elem(&ongoing_grpc_client_requests, creator_key, invocation, BPF_ANY) == 0;
    release_grpc_client_creator_request(creator_key);
    if (!published) {
        bpf_map_delete_elem(&grpc_client_request_states, &invocation->request_id);
    }
    return published;
}

static __always_inline u8 delete_grpc_client_creator_request_exact(
    const go_addr_key_t *creator_key, const grpc_client_request_id_t *request_id) {
    if (!creator_key || !request_id || !claim_grpc_client_creator_request(creator_key)) {
        return 0;
    }
    const grpc_client_func_invocation_t *current =
        bpf_map_lookup_elem(&ongoing_grpc_client_requests, creator_key);
    u8 deleted = 0;
    if (current && grpc_client_request_ids_match(&current->request_id, request_id)) {
        bpf_map_delete_elem(&ongoing_grpc_client_requests, creator_key);
        deleted = 1;
    }
    release_grpc_client_creator_request(creator_key);
    return deleted;
}

static __always_inline u8 allocate_grpc_client_request_id(const go_addr_key_t *creator,
                                                          grpc_client_request_id_t *request_id) {
    if (!creator || !request_id) {
        return 0;
    }

    const u64 process_start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS();
    const u32 cpu = bpf_get_smp_processor_id();
    const u32 zero = 0;
    u64 *sequence = bpf_map_lookup_elem(&grpc_client_request_sequences, &zero);
    if (!process_start_time || !sequence || *sequence == (u64)-1) {
        return 0;
    }

    // Uprobes are non-NMI programs and BPF execution is non-preemptible. This
    // per-CPU lane therefore has a single writer for the supported hook set.
    const u64 next = *sequence + 1;
    if (!next) {
        *sequence = (u64)-1;
        return 0;
    }
    *sequence = next;
    *request_id = (grpc_client_request_id_t){
        .creator = *creator,
        .process_start_time = process_start_time,
        .sequence = next,
        .cpu = cpu,
    };
    return 1;
}

static __always_inline u8
claim_grpc_client_request_handoffs(const grpc_client_request_id_t *request_id) {
    const u8 claimed = 1;
    return request_id &&
           bpf_map_update_elem(
               &grpc_client_request_handoff_claims, request_id, &claimed, BPF_NOEXIST) == 0;
}

static __always_inline void
release_grpc_client_request_handoffs(const grpc_client_request_id_t *request_id) {
    if (request_id) {
        bpf_map_delete_elem(&grpc_client_request_handoff_claims, request_id);
    }
}

static __always_inline u8 grpc_client_handoff_refs_match(
    const go_outgoing_trace_handoff_ref_t *left, const go_outgoing_trace_handoff_ref_t *right) {
    return left && right && bpf_memcmp(&left->egress, &right->egress, sizeof(left->egress)) == 0 &&
           outgoing_trace_tokens_match(&left->token, &right->token);
}

static __noinline void
poison_grpc_client_request_handoffs(const grpc_client_request_id_t *request_id) {
    if (!request_id) {
        return;
    }

#pragma unroll
    for (u8 slot = 0; slot < GRPC_CLIENT_HANDOFF_SLOTS; slot++) {
        grpc_client_handoff_slot_key_t slot_key = {
            .request_id = *request_id,
            .slot = slot,
        };
        const go_outgoing_trace_handoff_ref_t *stored =
            bpf_map_lookup_elem(&grpc_client_request_handoffs, &slot_key);
        if (stored) {
            const go_outgoing_trace_handoff_ref_t exact = *stored;
            cleanup_outgoing_trace_handoff_token(
                &exact.egress, exact.egress.pid, EVENT_HTTP_CLIENT, &exact.token);
            bpf_map_delete_elem(&grpc_client_request_handoffs, &slot_key);
        }
    }

    const u8 poisoned = k_grpc_client_handoff_poisoned;
    bpf_map_update_elem(&grpc_client_request_handoff_states, request_id, &poisoned, BPF_ANY);
}

static __noinline u8
cleanup_claimed_grpc_client_request(const grpc_client_request_id_t *request_id);

enum {
    k_grpc_client_handoff_registration_failed = 0,
    k_grpc_client_handoff_registered = 1,
    k_grpc_client_handoff_terminal = 2,
};

// The caller owns request_id's exact claim across this helper and all
// secondary publication. This prevents completion from cleaning authority
// between reference registration and legacy publication.
static __noinline u8
register_claimed_grpc_client_request_handoff(const grpc_client_request_id_t *request_id,
                                             const egress_key_t *egress,
                                             const outgoing_trace_token_t *token) {
    if (!grpc_client_request_id_is_current(request_id) || !egress ||
        !outgoing_trace_token_valid(token)) {
        return 0;
    }

    outgoing_trace_handoff_key_t authority_key = {};
    if (!claim_outgoing_trace_handoff_reference(egress, token, &authority_key)) {
        return k_grpc_client_handoff_registration_failed;
    }
    u8 result = k_grpc_client_handoff_registration_failed;
    u8 zero = 0;
    bpf_map_update_elem(&grpc_client_request_handoff_states, request_id, &zero, BPF_NOEXIST);
    u8 *state = bpf_map_lookup_elem(&grpc_client_request_handoff_states, request_id);
    grpc_client_func_invocation_t *canonical =
        bpf_map_lookup_elem(&grpc_client_request_states, request_id);
    if (!state || !canonical || canonical->terminal || (*state & k_grpc_client_handoff_poisoned)) {
        result = canonical && canonical->terminal ? k_grpc_client_handoff_terminal
                                                  : k_grpc_client_handoff_registration_failed;
        goto done;
    }

    const go_outgoing_trace_handoff_ref_t ref = {
        .egress = *egress,
        .token = *token,
    };
    u8 registered = 0;
    s8 available = -1;
#pragma unroll
    for (u8 slot = 0; slot < GRPC_CLIENT_HANDOFF_SLOTS; slot++) {
        grpc_client_handoff_slot_key_t slot_key = {
            .request_id = *request_id,
            .slot = slot,
        };
        const go_outgoing_trace_handoff_ref_t *stored =
            bpf_map_lookup_elem(&grpc_client_request_handoffs, &slot_key);
        if (stored && grpc_client_handoff_refs_match(stored, &ref)) {
            registered = 1;
            goto publication_done;
        }
        if (!stored && available < 0) {
            available = (s8)slot;
        }
    }

    if (available < 0) {
        poison_grpc_client_request_handoffs(request_id);
        goto done;
    }

    grpc_client_handoff_slot_key_t slot_key = {
        .request_id = *request_id,
        .slot = (u8)available,
    };
    if (bpf_map_update_elem(&grpc_client_request_handoffs, &slot_key, &ref, BPF_NOEXIST) != 0) {
        goto done;
    }
    const u8 next_state = *state | (1U << (u8)available);
    if (bpf_map_update_elem(
            &grpc_client_request_handoff_states, request_id, &next_state, BPF_EXIST) != 0) {
        bpf_map_delete_elem(&grpc_client_request_handoffs, &slot_key);
        goto done;
    }
    registered = 1;

publication_done:
    canonical = bpf_map_lookup_elem(&grpc_client_request_states, request_id);
    if (!canonical || canonical->terminal) {
        result = canonical && canonical->terminal ? k_grpc_client_handoff_terminal
                                                  : k_grpc_client_handoff_registration_failed;
        goto done;
    }
    result =
        registered ? k_grpc_client_handoff_registered : k_grpc_client_handoff_registration_failed;

done:
    release_outgoing_trace_handoff_key(&authority_key);
    return result;
}

static __noinline u8
cleanup_claimed_grpc_client_request_handoffs(const grpc_client_request_id_t *request_id) {
    if (!request_id) {
        return 0;
    }

    u8 cleaned = 0;
#pragma unroll
    for (u8 slot = 0; slot < GRPC_CLIENT_HANDOFF_SLOTS; slot++) {
        grpc_client_handoff_slot_key_t slot_key = {
            .request_id = *request_id,
            .slot = slot,
        };
        const go_outgoing_trace_handoff_ref_t *stored =
            bpf_map_lookup_elem(&grpc_client_request_handoffs, &slot_key);
        if (stored) {
            const go_outgoing_trace_handoff_ref_t exact = *stored;
            cleanup_outgoing_trace_handoff_token(
                &exact.egress, exact.egress.pid, EVENT_HTTP_CLIENT, &exact.token);
            bpf_map_delete_elem(&grpc_client_request_handoffs, &slot_key);
            cleaned = 1;
        }
    }
    bpf_map_delete_elem(&grpc_client_request_handoff_states, request_id);
    return cleaned;
}

static __always_inline u8 claim_grpc_client_stream_request(const go_addr_key_t *stream_key) {
    const u8 claimed = 1;
    return stream_key &&
           bpf_map_update_elem(
               &grpc_client_stream_request_claims, stream_key, &claimed, BPF_NOEXIST) == 0;
}

static __always_inline void release_grpc_client_stream_request(const go_addr_key_t *stream_key) {
    if (stream_key) {
        bpf_map_delete_elem(&grpc_client_stream_request_claims, stream_key);
    }
}

static __always_inline u8 delete_grpc_client_stream_request_exact(
    const go_addr_key_t *stream_key, const grpc_client_request_id_t *request_id) {
    if (!stream_key || !request_id || !claim_grpc_client_stream_request(stream_key)) {
        return 0;
    }
    const grpc_client_request_id_t *current =
        bpf_map_lookup_elem(&grpc_client_stream_requests, stream_key);
    u8 deleted = 0;
    if (grpc_client_request_ids_match(current, request_id)) {
        bpf_map_delete_elem(&grpc_client_stream_requests, stream_key);
        deleted = 1;
    }
    release_grpc_client_stream_request(stream_key);
    return deleted;
}

static __noinline u8 reserve_grpc_client_stream_request(
    const go_addr_key_t *stream_key, const grpc_client_request_id_t *request_id) {
    if (!stream_key || !grpc_client_request_id_is_current(request_id) ||
        !claim_grpc_client_stream_request(stream_key)) {
        return 0;
    }

    if (bpf_map_update_elem(&grpc_client_stream_requests, stream_key, request_id, BPF_NOEXIST) ==
        0) {
        release_grpc_client_stream_request(stream_key);
        return 1;
    }

    const grpc_client_request_id_t *located =
        bpf_map_lookup_elem(&grpc_client_stream_requests, stream_key);
    if (!located) {
        release_grpc_client_stream_request(stream_key);
        return 0;
    }
    const grpc_client_request_id_t existing = *located;
    if (grpc_client_request_ids_match(&existing, request_id)) {
        release_grpc_client_stream_request(stream_key);
        return 1;
    }

    // A current non-terminal canonical request owns this pointer. Everything
    // else is a bounded stale locator and is safe to replace while the stream
    // key claim excludes a concurrent cleanup/replacement.
    u8 stale = !grpc_client_request_id_is_current(&existing);
    if (!stale) {
        const grpc_client_func_invocation_t *canonical =
            bpf_map_lookup_elem(&grpc_client_request_states, &existing);
        stale = !canonical || canonical->terminal;
    }
    if (!stale) {
        release_grpc_client_stream_request(stream_key);
        return 0;
    }

    located = bpf_map_lookup_elem(&grpc_client_stream_requests, stream_key);
    if (!grpc_client_request_ids_match(located, &existing)) {
        release_grpc_client_stream_request(stream_key);
        return 0;
    }
    bpf_map_delete_elem(&grpc_client_stream_requests, stream_key);
    const u8 reserved =
        bpf_map_update_elem(&grpc_client_stream_requests, stream_key, request_id, BPF_NOEXIST) == 0;
    release_grpc_client_stream_request(stream_key);
    return reserved;
}

static __always_inline u8 load_current_grpc_client_stream_request(
    const go_addr_key_t *stream_key, grpc_client_request_id_t *request_id) {
    if (!stream_key || !request_id) {
        return 0;
    }
    const grpc_client_request_id_t *located =
        bpf_map_lookup_elem(&grpc_client_stream_requests, stream_key);
    if (!located) {
        return 0;
    }
    const grpc_client_request_id_t exact = *located;
    if (!grpc_client_request_id_is_current(&exact)) {
        delete_grpc_client_stream_request_exact(stream_key, &exact);
        return 0;
    }
    *request_id = exact;
    return 1;
}

static __noinline u8
cleanup_claimed_grpc_client_request(const grpc_client_request_id_t *request_id) {
    if (!request_id) {
        return 0;
    }

    grpc_client_func_invocation_t *canonical =
        bpf_map_lookup_elem(&grpc_client_request_states, request_id);
    go_addr_key_t stream_key = {};
    u8 has_stream = 0;
    if (canonical) {
        stream_key = canonical->stream_key;
        has_stream = canonical->has_stream;
    }

    const u8 cleaned = cleanup_claimed_grpc_client_request_handoffs(request_id);
    if (has_stream) {
        delete_grpc_client_stream_request_exact(&stream_key, request_id);
    }

    delete_grpc_client_creator_request_exact(&request_id->creator, request_id);
    bpf_map_delete_elem(&grpc_client_request_states, request_id);
    return cleaned || canonical;
}

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, grpc_srv_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_server_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} cached_grpc_client_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_stream_key_t);
    __type(value, grpc_client_func_invocation_t); // stored info for the client request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_streams SEC(".maps");

// TODO: use go_addr_key_t as key
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_header_writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, transport_new_client_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} transport_new_client_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, grpc_framer_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_framer_invocation_map SEC(".maps");

// net.Conn* → connection_info. Populated in NewStream, read in WriteHeaders.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_conn_ptr_to_conn SEC(".maps");

// hdr_ptr → {invocation, conn_ptr}. executeAndPut stashes on the NewStream
// goroutine; originateStream reads on the loopyWriter goroutine once the
// stream_id is assigned, then builds {conn_ptr, stream_id} for ongoing_streams
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, pending_h2_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} pending_h2_invocations SEC(".maps");

// Per-stream tp (Go gRPC server). operateHeaders writes, handleStream reads.
// Avoids the last-writer-wins race on the transport-keyed ongoing_grpc_transports
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, stream_key_t);
    __type(value, tp_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_server_stream_tps SEC(".maps");
