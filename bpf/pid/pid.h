// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <logger/bpf_dbg.h>

#include <pid/maps/pid_cache.h>
#include <pid/maps/valid_pids.h>

#include <pid/pid_helpers.h>

#include <pid/types/pid_data.h>

volatile const s32 filter_pids = 0;

enum { k_prime_hash = 192053 }; // closest prime to k_max_concurrent_pids * 64

// out of range makes the lookup in pid_matches() miss, which fails open
_Static_assert((k_prime_hash - 1) / 64 < k_max_concurrent_pids,
               "k_prime_hash exceeds the valid_pids index space");

static __always_inline u8 pid_matches(pid_data_t *p) {
    // combine the namespace id and the pid into one single u64
    const u64 k = (((u64)p->ns) << 32) | p->pid;

    // divide with prime number lower than max pids * 64, modulo with primes gives good hash functions
    const u32 h = (u32)(k % k_prime_hash);
    const u32 segment = h / 64; // divide by the segment size (8 bytes) to find the segment
    const u32 bit = h & 63;     // lowest 64 bits gives us the placement inside the segment

    u64 *v = bpf_map_lookup_elem(&valid_pids, &segment);
    if (!v) {
        // This is an error of some kind, we should always find the segment
        bpf_dbg_printk("Error looking up PID, segment=%d", segment);
        return 1;
    }

    return ((*v) >> bit) & 1;
}

static __always_inline u8 task_matches(u32 ns_pid, u32 ns_ppid, u32 pid_ns_id) {
    pid_data_t p_key = {.pid = ns_pid, .ns = pid_ns_id};

    if (pid_matches(&p_key)) {
        return 1;
    }

    // no parent to inherit the selection from (or its pid could not be read)
    if (ns_ppid == 0) {
        return 0;
    }

    pid_data_t pp_key = {.pid = ns_ppid, .ns = pid_ns_id};

    return pid_matches(&pp_key);
}

// pid_cache is keyed by host pid and holds both answers: unselected processes
// hit these probes on every syscall and must not repeat ns_pid_ppid().
// Userspace clears the cache whenever the filter changes.
static __always_inline u32 valid_pid(u64 id) {
    const u32 host_pid = id >> 32;
    // accept all PIDs if debugging OTEL_EBPF_BPF_PID_FILTER_OFF option is set
    if (!filter_pids) {
        return host_pid;
    }

    u32 *found = bpf_map_lookup_elem(&pid_cache, &host_pid);
    if (found) {
        return *found;
    }

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;

    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    if (ns_pid == 0) {
        return 0;
    }

    if (task_matches((u32)ns_pid, (u32)ns_ppid, pid_ns_id)) {
        bpf_map_update_elem(&pid_cache, &host_pid, &host_pid, BPF_ANY);
        return host_pid;
    }

    // NOEXIST: never clobber a positive entry userspace put in concurrently
    const u32 not_selected = 0;
    bpf_map_update_elem(&pid_cache, &host_pid, &not_selected, BPF_NOEXIST);

    return 0;
}
