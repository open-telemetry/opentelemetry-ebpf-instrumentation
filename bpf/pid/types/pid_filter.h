// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

// How valid_pid() numbers the current task the way OBI's /proc numbers it.
// bpf2go exports it to pkg/ebpf/common.
enum pid_namespace_mode : u32 {
    k_pid_ns_mode_init = 0,         // OBI's /proc is the initial pid namespace
    k_pid_ns_mode_pod_helper = 1,   // OBI's /proc is a pod's: bpf_get_ns_current_pid_tgid()
    k_pid_ns_mode_pod_emulated = 2, // same, for kernels and program types without the helper
};

// One bit per pid, as OBI's /proc numbers it: bit pid % 64 of word pid / 64.
// PID_MAX_LIMIT is 2^22 on 64-bit kernels (include/linux/threads.h), so every
// pid has a bit. 512 KB. bpf2go exports it to pkg/ebpf/common.
enum valid_pids_size : u32 {
    k_valid_pids_words = (1 << 22) / 64,
};
