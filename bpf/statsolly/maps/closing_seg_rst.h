// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// RST flag of the last segment that could reset a closing socket
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct sock *);
    __type(value, u8);
    __uint(max_entries, 1 << 14);
    __uint(pinning, OBI_PIN_INTERNAL);
} closing_seg_rst SEC(".maps");
