// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/msg_buffer.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, egress_key_t);
    __type(value, msg_buffer_t);
    __uint(max_entries, 1000);
    __uint(pinning, OBI_PIN_INTERNAL);
} msg_buffers SEC(".maps");

// unsorted: both ends of a same-host connection sort to the same ports and would share the entry
static __always_inline egress_key_t msg_buffer_key(const connection_info_t *conn) {
    const egress_key_t key = {
        .s_port = conn->s_port,
        .d_port = conn->d_port,
    };

    return key;
}
