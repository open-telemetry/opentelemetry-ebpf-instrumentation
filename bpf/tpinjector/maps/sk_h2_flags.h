// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

enum {
    // A response block was seen on this socket, so we are the server on it. Later responses
    // can carry :status by dyn-table index, which the opener check cannot recognize.
    k_h2_sk_server = 1 << 0,
    // The sender emitted its own traceparent here, matched by name. Later requests can
    // reference that name, or the whole field, by dynamic table index, leaving nothing on the
    // wire to scan for — but an index only exists because the encoder inserted the entry while
    // the name was still on the wire, so this bit covers every later reference exactly. It
    // does not cover a connection whose insertions predate attachment.
    k_h2_sk_app_tp = 1 << 1,
};

// Per-socket facts a single frame cannot establish. Auto-freed on socket close.
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, u8);
} sk_h2_flags SEC(".maps");
