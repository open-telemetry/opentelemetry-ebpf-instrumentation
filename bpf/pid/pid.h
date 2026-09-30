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
// the inode of the pid namespace of OBI's /proc, as stat() reports it
volatile const u64 obi_pid_ns_ino = 0;

// The level of that namespace, found on the first task seen in it or below it.
// 0 until then: level 0 is the initial namespace, which uses init mode.
u32 obi_pid_ns_level = 0;

// numbers[i] is the pid in the namespace at level i, from the initial one (0)
// down to the task's own (pid->level). 0 when entry i is not in OBI's pid
// namespace. Comparing the inode is enough: all pid namespace inodes live on
// the one nsfs mount.
static __always_inline u32 pid_nr_at(const struct pid *pid, const u32 level, const u32 i) {
    if (i > level) {
        return 0;
    }

    struct upid upid = {};
    bpf_probe_read_kernel(&upid, sizeof(upid), &pid->numbers[i]);

    if (BPF_CORE_READ(upid.ns, ns.inum) != obi_pid_ns_ino) {
        return 0;
    }

    return (u32)upid.nr;
}

static __always_inline u32 find_obi_pid_ns_level(const struct pid *pid, const u32 level) {
    for (u32 i = 1; i <= k_max_pid_ns_level; i++) {
        if (i > level) {
            break;
        }
        if (pid_nr_at(pid, level, i) != 0) {
            return i;
        }
    }

    return 0;
}

// The pid of task in OBI's pid namespace, the entry pid_nr_ns() reads: it
// exists for a task in that namespace and in every namespace below it (pods on
// a node that is itself a container, a sandbox inside a sidecar's pod). 0 for
// a task outside. The level is always read from the task's own struct pid, not
// from nsproxy->pid_ns_for_children, which names the namespace of its future
// children.
static __always_inline u32 pid_in_obi_pid_ns(const struct task_struct *task) {
    const struct pid *pid = BPF_CORE_READ(task, group_leader, thread_pid);
    const u32 level = BPF_CORE_READ(pid, level);

    if (obi_pid_ns_level == 0) {
        obi_pid_ns_level = find_obi_pid_ns_level(pid, level);
    }

    return pid_nr_at(pid, level, obi_pid_ns_level);
}

static __always_inline u32 obi_pid(u64 id) {
    if (pid_ns_mode == k_pid_ns_mode_init) {
        return id >> 32;
    }

    return pid_in_obi_pid_ns((const struct task_struct *)bpf_get_current_task());
}

static __always_inline u32 obi_parent_pid(void) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    const struct task_struct *parent = BPF_CORE_READ(task, real_parent);

    if (pid_ns_mode == k_pid_ns_mode_init) {
        return BPF_CORE_READ(parent, tgid);
    }

    const struct pid *pid = BPF_CORE_READ(parent, group_leader, thread_pid);
    return pid_nr_at(pid, BPF_CORE_READ(pid, level), obi_pid_ns_level);
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
