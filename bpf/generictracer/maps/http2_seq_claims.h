// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

// ordinals claimed via BPF_NOEXIST: the only atomic RMW kprobes have on 5.8
typedef struct http2_seq_claim {
    u64 conn_id;
    u32 seq;
    u32 _pad;
} http2_seq_claim_t;

enum {
    // how many taken slots one claimer steps past before giving up
    k_seq_claim_attempts = 8,
    // no ordinal claimed: user space must distrust the decoders
    k_h2_seq_unreliable = 0xffffffff,
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, http2_seq_claim_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} http2_seq_claims SEC(".maps");
