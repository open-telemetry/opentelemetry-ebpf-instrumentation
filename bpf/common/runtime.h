// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <maps/active_unix_socks.h>
#include <maps/python_current_context.h>

#include <pid/pid_helpers.h>

static __always_inline u64 extra_runtime_id_with_task_id(const u64 id) {
    const u32 *inode_num = (const u32 *)bpf_map_lookup_elem(&active_unix_socks, &id);

    return inode_num ? (u64)(*inode_num) : 0;
}

static __always_inline u64 extra_runtime_id() {
    const u64 id = bpf_get_current_pid_tgid();
    u64 *context = bpf_map_lookup_elem(&python_current_context, &id);
    if (context) {
        bpf_dbg_printk(
            "extra_runtime_id: LOOKUP python_current_context[host_id=%llx] = %llx", id, *context);
        return (u64)(*context);
    }
    return extra_runtime_id_with_task_id(id);
}
