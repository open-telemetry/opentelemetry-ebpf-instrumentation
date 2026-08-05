// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

typedef struct process_readiness {
    u64 start_time;
    u32 epoch;
    u32 config_epoch;
    u8 ready;
    u8 auto_sdk_global_ready;
    u8 _pad[6];
} process_readiness_t;

#ifdef __bpf__
#define OBI_PRESERVE_ACCESS_INDEX __attribute__((preserve_access_index))
#else
#define OBI_PRESERVE_ACCESS_INDEX
#endif

struct task_struct___legacy_start_time {
    u64 real_start_time;
} OBI_PRESERVE_ACCESS_INDEX;

struct task_struct___start_boottime {
    u64 start_boottime;
} OBI_PRESERVE_ACCESS_INDEX;

enum {
    k_process_clock_tick_ns = 10 * 1000 * 1000,
};

static __always_inline u64 current_process_start_boottime_ns() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (!leader) {
        leader = task;
    }

    u64 start_time;
    if (bpf_core_field_exists(((struct task_struct___start_boottime *)0)->start_boottime)) {
        const struct task_struct___start_boottime *modern_leader =
            (const struct task_struct___start_boottime *)leader;
        start_time = BPF_CORE_READ(modern_leader, start_boottime);
    } else if (bpf_core_field_exists(
                   ((struct task_struct___legacy_start_time *)0)->real_start_time)) {
        const struct task_struct___legacy_start_time *legacy_leader =
            (const struct task_struct___legacy_start_time *)leader;
        start_time = BPF_CORE_READ(legacy_leader, real_start_time);
    } else {
        return 0;
    }
    return start_time;
}

#ifndef OBI_CURRENT_PROCESS_START_BOOTTIME_NS
#define OBI_CURRENT_PROCESS_START_BOOTTIME_NS current_process_start_boottime_ns
#endif

// Userspace obtains process start time from /proc/<pid>/stat, whose Linux ABI
// is clock-tick based. Preserve that representation for readiness, admission,
// and all other userspace-bound identities.
static __always_inline u64 current_process_start_time_ns() {
    const u64 start_time = OBI_CURRENT_PROCESS_START_BOOTTIME_NS();
    return start_time - (start_time % k_process_clock_tick_ns);
}

#ifndef OBI_CURRENT_PROCESS_START_TIME_NS
#define OBI_CURRENT_PROCESS_START_TIME_NS current_process_start_time_ns
#endif

static __always_inline u8 process_incarnation_matches_current(const u32 host_tgid,
                                                              const u64 start_time) {
    if (!start_time) {
        return 0;
    }
    if ((u32)(bpf_get_current_pid_tgid() >> 32) != host_tgid) {
        return 0;
    }
    return OBI_CURRENT_PROCESS_START_TIME_NS() == start_time;
}

// BPF-only transport identities retain the full kernel value so two process
// incarnations inside one userspace clock tick remain distinct.
static __always_inline u8 process_incarnation_matches_current_exact(const u32 host_tgid,
                                                                    const u64 start_time) {
    if (!start_time) {
        return 0;
    }
    if ((u32)(bpf_get_current_pid_tgid() >> 32) != host_tgid) {
        return 0;
    }
    return OBI_CURRENT_PROCESS_START_BOOTTIME_NS() == start_time;
}

static __always_inline u8 process_incarnation_matches(const u64 expected_start_time,
                                                      const u64 actual_start_time) {
    return expected_start_time && actual_start_time && expected_start_time == actual_start_time;
}

#undef OBI_PRESERVE_ACCESS_INDEX
