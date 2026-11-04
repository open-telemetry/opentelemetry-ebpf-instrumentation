// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

static __always_inline void
read_skb_bytes(const void *skb, u32 offset, unsigned char *buf, const u32 len, const u32 max_len) {
    enum : u32 { k_block_size = 16 };
    const u32 niter = max_len / k_block_size;

    u64 remaining = len;
    bpf_clamp_umax(remaining, max_len);

    for (u32 i = 0; i < niter; ++i) {
        if (!remaining) {
            return;
        }
        u64 chunk = remaining;
        bpf_clamp_umax(chunk, k_block_size);
        bpf_clamp_umin(chunk, 1);
        // Reassert the destination bound independently of the remaining-length tracking.
        u64 pos = i * k_block_size;
        bpf_clamp_umax(pos, max_len - k_block_size);
        bpf_skb_load_bytes(skb, offset + pos, buf + pos, chunk);
        remaining -= chunk;
    }
}
