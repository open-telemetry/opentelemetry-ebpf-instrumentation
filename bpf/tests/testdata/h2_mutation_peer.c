// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>
#include <common/pin_internal.h>

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
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} fault_mask SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, OBI_PIN_INTERNAL);
} invocations SEC(".maps");

static const unsigned char expected_hpack[k_h2_tp_hpack_size] =
    "\x00\x0btraceparent\x37"
    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

static __always_inline bool mutation_fault(u32 boundary) {
    const u32 zero = 0;
    const u64 *mask = bpf_map_lookup_elem(&fault_mask, &zero);
    return mask && (*mask & (1ULL << boundary));
}

#define H2_SOCKET_TRANSACTION_FAULT(boundary) mutation_fault(boundary)
#include <tpinjector/h2_write_transaction.h>

// Loaded only by the privileged same-peer rollback test.
SEC("sk_msg")
int h2_mutation_peer(struct sk_msg_md *msg) {
    enum { k_test_payload_len = 8 };

    const u32 zero = 0;
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
