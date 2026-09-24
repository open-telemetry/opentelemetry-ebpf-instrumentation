// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>
#include <common/pin_internal.h>

static __always_inline long
h2_test_msg_pull_data(struct sk_msg_md *msg, u32 start, u32 end, u64 flags);
static __always_inline long
h2_test_msg_push_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags);
static __always_inline long
h2_test_msg_pop_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags);

#define bpf_msg_pull_data h2_test_msg_pull_data
#define bpf_msg_push_data h2_test_msg_push_data
#define bpf_msg_pop_data h2_test_msg_pop_data
#include <tpinjector/h2_write_transaction.h>
#undef bpf_msg_pop_data
#undef bpf_msg_push_data
#undef bpf_msg_pull_data

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u32));
    __uint(pinning, OBI_PIN_INTERNAL);
} sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, OBI_PIN_INTERNAL);
} invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} fault_mask SEC(".maps");

struct h2_test_helper_calls {
    u32 pull;
    u32 pop;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct h2_test_helper_calls);
    __uint(pinning, OBI_PIN_INTERNAL);
} helper_calls SEC(".maps");

static const unsigned char expected_hpack[k_h2_tp_hpack_size] =
    "\x00\x0btraceparent\x37"
    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

enum {
    k_h2_test_push_fault_bit = 16,
    k_h2_test_pop_fault_bit_offset = 32,
};

static __always_inline bool h2_test_fault_enabled(u32 bit) {
    const u32 zero = 0;
    const u64 *mask = bpf_map_lookup_elem(&fault_mask, &zero);
    return mask && (*mask & (1ULL << bit));
}

static __always_inline struct h2_test_helper_calls *h2_test_calls(void) {
    const u32 zero = 0;
    return bpf_map_lookup_elem(&helper_calls, &zero);
}

static __always_inline long
h2_test_msg_pull_data(struct sk_msg_md *msg, u32 start, u32 end, u64 flags) {
    struct h2_test_helper_calls *calls = h2_test_calls();
    if (calls && h2_test_fault_enabled(++calls->pull)) {
        return -1;
    }
    return bpf_msg_pull_data(msg, start, end, flags);
}

static __always_inline long
h2_test_msg_push_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags) {
    if (h2_test_fault_enabled(k_h2_test_push_fault_bit)) {
        return -1;
    }
    return bpf_msg_push_data(msg, start, len, flags);
}

static __always_inline long
h2_test_msg_pop_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags) {
    struct h2_test_helper_calls *calls = h2_test_calls();
    if (calls && h2_test_fault_enabled(k_h2_test_pop_fault_bit_offset + ++calls->pop)) {
        return -1;
    }
    return bpf_msg_pop_data(msg, start, len, flags);
}

// Loaded only by the privileged same-peer rollback test.
SEC("sk_msg")
int h2_mutation_peer(struct sk_msg_md *msg) {
    enum { k_test_payload_len = 8 };

    const u32 zero = 0;
    struct h2_test_helper_calls *calls = bpf_map_lookup_elem(&helper_calls, &zero);
    if (calls) {
        calls->pull = 0;
        calls->pop = 0;
    }

    u32 *invocation_count = bpf_map_lookup_elem(&invocations, &zero);
    if (invocation_count) {
        (*invocation_count)++;
    }

    const h2_socket_transaction_outcome_t outcome = h2_write_socket_transaction(
        msg, 0, k_test_payload_len, k_h2_frame_header_len + k_test_payload_len, expected_hpack);
    if (outcome == k_h2_socket_transaction_rollback_uncertain) {
        return SK_DROP;
    }
    return SK_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
