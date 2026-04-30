// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <pid/maps/map_sizing.h>

// Same bitmap shape as valid_pids, but populated with both kprobe-tracked AND
// Go-tracked PIDs. Used by sk_msg only — generictracer's kprobes keep using
// valid_pids (kprobe-only) to avoid double-spanning Go binaries that already
// have uprobes
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, k_max_concurrent_pids);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} tp_valid_pids SEC(".maps");
