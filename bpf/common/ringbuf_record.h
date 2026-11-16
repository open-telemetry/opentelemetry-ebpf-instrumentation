// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// The kernel stores each record with an 8-byte header and rounds the total up to 8 bytes
// (__bpf_ringbuf_reserve in kernel/bpf/ringbuf.c).
enum { k_ringbuf_record_align = 8 };

// ringbuf_record_size returns how many bytes a record of the given size takes in the ring buffer,
// as counted by BPF_RB_AVAIL_DATA.
static __always_inline u64 ringbuf_record_size(u64 size) {
    return (size + BPF_RINGBUF_HDR_SZ + k_ringbuf_record_align - 1) &
           ~(u64)(k_ringbuf_record_align - 1);
}
