// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

// Port-only (no netns) version of listening_ports, for use in socket filter
// programs where the network namespace is not reliably accessible from __sk_buff.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u16);
    __type(value, bool);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} unreadable_buffer_ports SEC(".maps");
