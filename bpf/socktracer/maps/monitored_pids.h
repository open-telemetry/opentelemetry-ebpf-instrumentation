// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <pid/maps/map_sizing.h>

// PIDs socktracer instruments, keyed by host tgid. Separate from valid_pids, which
// excludes Go/uprobe processes.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_max_concurrent_pids);
    __type(key, u32);
    __type(value, u8);
    __uint(pinning, OBI_PIN_INTERNAL);
} socktracer_monitored_pids SEC(".maps");

static __always_inline bool socktracer_pid_monitored(u64 pid_tgid) {
    const u32 pid = (u32)(pid_tgid >> 32);
    return bpf_map_lookup_elem(&socktracer_monitored_pids, &pid) != NULL;
}
