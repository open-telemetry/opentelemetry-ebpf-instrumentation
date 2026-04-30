// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <pid/maps/pid_cache.h>
#include <pid/pid.h> // for filter_pids, k_prime_hash, ns_pid_ppid
#include <pid/types/pid_data.h>

#include <tpinjector/maps/tp_valid_pids.h>

// Mirrors pid_matches() from pid/pid.h but reads tp_valid_pids (which includes
// both kprobe-tracked and Go-tracked PIDs)
static __always_inline u8 tp_pid_matches(pid_data_t *p) {
    const u64 k = (((u64)p->ns) << 32) | p->pid;
    const u32 h = (u32)(k % k_prime_hash);
    const u32 segment = h / 64;
    const u32 bit = h & 63;

    u64 *v = bpf_map_lookup_elem(&tp_valid_pids, &segment);
    if (!v) {
        return 1;
    }
    return ((*v) >> bit) & 1;
}

// Mirrors valid_pid() but uses tp_valid_pids. sk_msg uses this so that Go
// binaries (uprobe-instrumented but not kprobe-tracked) still pass the gate
static __always_inline u32 tp_valid_pid(u64 id) {
    const u32 a_pid = id >> 32;
    if (!filter_pids) {
        return a_pid;
    }

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    int ns_ppid = 0;
    u32 pid_ns_id = 0;
    u32 ns_pid = a_pid;
    ns_pid_ppid(task, (int *)&ns_pid, &ns_ppid, &pid_ns_id);

    if (ns_pid != 0) {
        pid_data_t p_key = {.pid = ns_pid, .ns = pid_ns_id};
        if (tp_pid_matches(&p_key)) {
            return a_pid;
        }
        if (ns_ppid != 0) {
            pid_data_t pp_key = {.pid = ns_ppid, .ns = pid_ns_id};
            if (tp_pid_matches(&pp_key)) {
                return a_pid;
            }
        }
    }
    return 0;
}
