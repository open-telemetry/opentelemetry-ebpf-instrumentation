// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/http_buf_size.h>
#include <common/pin_internal.h>

enum { k_msg_buffer_size_max = 8192 };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, unsigned char[k_msg_buffer_size_max]);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} msg_buffer_mem SEC(".maps");

// When sock_msg is installed it disables the kprobes attached to tcp_sendmsg.
// We use this data structure to provide the buffer to the tcp_sendmsg logic,
// because we can't read the bvec physical pages.
typedef struct msg_buffer {
    // This is a safety net in case there's been a CPU migration
    // and the stored buffer in the per-cpu map cannot be used anymore.
    unsigned char fallback_buf[k_kprobes_http2_buf_size];
    u16 pos;
    u16 real_size;
    // Store the CPU id used to save the buffer in `msg_buffer_mem`. This
    // will then be used as a guard in different execution contexts.
    u32 cpu_id;
} msg_buffer_t;

// Copies as much of the message at src as msg_buffer_mem holds into dst, and
// returns the number of bytes written — which is what the tcp_sendmsg kprobe
// takes as the extent of this message. dst must have room for
// k_msg_buffer_size_max bytes, and that many bytes at src must be readable.
//
// The length is bounded with bpf_clamp_umax() rather than min(). Both clamp the
// value, but only the asm form bounds the register the length is passed in: min()
// compiles to a compare and a select whose copy clang may hoist above the
// compare, leaving the verifier to recover the range through scalar-ID linking
// that older kernels do not have. bpf_clamp_umax() refines the register in place,
// so any later move carries the bound with it.
//
// Returns 0 when nothing was written. bpf_probe_read_kernel() is all-or-nothing
// and dst is a per-CPU buffer that nothing clears between messages, so reporting
// a length the read did not produce would hand the protocol parsers whatever the
// previous message on this CPU left behind.
static __always_inline u16 msg_buffer_copy(unsigned char *dst, const void *src, u32 msg_size) {
    u32 len = msg_size;
    bpf_clamp_umax(len, k_msg_buffer_size_max);

    if (len == 0 || bpf_probe_read_kernel(dst, len, src) != 0) {
        return 0;
    }

    return (u16)len;
}
