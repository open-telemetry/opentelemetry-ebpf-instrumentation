// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/http_types.h>

typedef struct {
    unsigned char data[MIN_HTTP2_SIZE];
    u32 len;
} recv_prefix_t;

// The joined buffer has room for max_read plus MIN_HTTP2_SIZE bytes.
static __always_inline u32 append_recv_prefix(recv_prefix_t *prefix,
                                              const unsigned char *buf,
                                              u32 size,
                                              unsigned char *joined,
                                              const u32 max_read) {
    u64 kept = prefix->len;
    bpf_clamp_umax(kept, MIN_HTTP2_SIZE);
    __builtin_memset(joined, 0, MIN_HTTP2_SIZE);
    if (kept) {
        bpf_probe_read_kernel(joined, kept, prefix->data);
    }
    bpf_clamp_umax(kept, MIN_HTTP2_SIZE);
    u64 read_size = size;
    bpf_clamp_umax(read_size, max_read);
    bpf_probe_read_kernel(joined + kept, read_size, buf);
    bpf_clamp_umax(kept, MIN_HTTP2_SIZE);
    bpf_clamp_umax(read_size, max_read);
    const u32 total = kept + read_size;
    // Check the method prefix, rather than delaying other protocols such as NATS PUB.
    const bool http_prefix =
        (joined[0] == 'G' && (total < 2 || joined[1] == 'E') && (total < 3 || joined[2] == 'T')) ||
        (joined[0] == 'P' &&
         (((total < 2 || joined[1] == 'O') && (total < 3 || joined[2] == 'S')) ||
          ((total < 2 || joined[1] == 'U') && (total < 3 || joined[2] == 'T')) ||
          ((total < 2 || joined[1] == 'A') && (total < 3 || joined[2] == 'T')))) ||
        (joined[0] == 'D' && (total < 2 || joined[1] == 'E') && (total < 3 || joined[2] == 'L')) ||
        (joined[0] == 'H' &&
         (((total < 2 || joined[1] == 'E') && (total < 3 || joined[2] == 'A')) ||
          ((total < 2 || joined[1] == 'T') && (total < 3 || joined[2] == 'T')))) ||
        (joined[0] == 'O' && (total < 2 || joined[1] == 'P') && (total < 3 || joined[2] == 'T'));
    const bool h2_prefix =
        joined[0] == 'P' && (total < 2 || joined[1] == 'R') && (total < 3 || joined[2] == 'I');
    if (total == 1 || (http_prefix && total < MIN_HTTP_SIZE) ||
        (h2_prefix && total < MIN_HTTP2_SIZE)) {
        u64 pending = total;
        bpf_clamp_umax(pending, MIN_HTTP2_SIZE);
        bpf_probe_read_kernel(prefix->data, pending, joined);
        prefix->len = total;
        return 0;
    }
    prefix->len = 0;
    return total;
}
