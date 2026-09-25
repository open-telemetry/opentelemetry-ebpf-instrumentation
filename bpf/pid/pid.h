// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <pid/maps/valid_pids.h>

#include <pid/pid_helpers.h>

#include <pid/types/pid_filter.h>

// In this file, as in the rest of OBI, "pid" means the process id: the kernel's
// tgid. Thread ids are "tid".

volatile const s32 filter_pids = 0;

volatile const u32 pid_ns_mode = k_pid_ns_mode_init;
// the pid namespace of OBI's /proc, as stat() reports it
volatile const u64 obi_pid_ns_dev = 0;
volatile const u64 obi_pid_ns_ino = 0;

// The pid of task in OBI's pid namespace, or 0 when the task does not live
// directly in it: the rule bpf_get_ns_current_pid_tgid() applies. The level
// comes from the task's own struct pid, not from nsproxy->pid_ns_for_children,
// which names the namespace of its future children. Comparing the inode is
// enough: all pid namespace inodes live on the one nsfs mount.
static __always_inline u32 pid_in_obi_pid_ns(const struct task_struct *task) {
    const struct pid *pid = BPF_CORE_READ(task, group_leader, thread_pid);
    const unsigned int level = BPF_CORE_READ(pid, level);

    struct upid upid = {};
    bpf_probe_read_kernel(&upid, sizeof(upid), &pid->numbers[level]);

    if (BPF_CORE_READ(upid.ns, ns.inum) != obi_pid_ns_ino) {
        return 0;
    }

    return (u32)upid.nr;
}

// The key userspace publishes for the current task in valid_pids, or 0 when
// the task is outside OBI's pid namespace.
static __always_inline u32 obi_pid(u64 id) {
    if (pid_ns_mode == k_pid_ns_mode_init) {
        return id >> 32;
    }

    if (pid_ns_mode == k_pid_ns_mode_pod_helper) {
        struct bpf_pidns_info ns = {};
        if (bpf_get_ns_current_pid_tgid(obi_pid_ns_dev, obi_pid_ns_ino, &ns, sizeof(ns))) {
            return 0;
        }

        return ns.tgid;
    }

    return pid_in_obi_pid_ns((const struct task_struct *)bpf_get_current_task());
}

// Same key for the parent of the current task. The helper only answers for
// the current task, so both pod modes read the parent's struct pid.
static __always_inline u32 obi_parent_pid(void) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    const struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    if (pid_ns_mode == k_pid_ns_mode_init) {
        return BPF_CORE_READ(parent, tgid);
    }

    return pid_in_obi_pid_ns(parent);
}

// A pid past the last word cannot occur while PID_MAX_LIMIT is 2^22; it is
// rejected rather than accepted.
static __always_inline bool pid_selected(u32 pid) {
    const u32 word = pid / 64;

    const u64 *bits = bpf_map_lookup_elem(&valid_pids, &word);
    if (!bits) {
        return false;
    }

    return (*bits >> (pid & 63)) & 1;
}

// A task passes when its own bit or its parent's is set, so children forked
// after discovery are covered until userspace allows them too. Returns the pid
// OBI's /proc reports for a task that passes, 0 otherwise: callers match it
// against pids userspace read from that /proc, such as the USDT ip map.
static __always_inline u32 valid_pid(u64 id) {
    const u32 host_pid = id >> 32;
    // accept all PIDs if debugging OTEL_EBPF_BPF_PID_FILTER_OFF option is set.
    // This returns the host pid: in pod mode it is not the pid OBI's /proc
    // reports, so lookups keyed by that pid, such as the USDT ip map, miss.
    if (!filter_pids) {
        return host_pid;
    }

    const u32 pid = obi_pid(id);
    if (pid == 0) {
        return 0;
    }

    if (pid_selected(pid) || pid_selected(obi_parent_pid())) {
        return pid;
    }

    return 0;
}
