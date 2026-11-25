// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_addr_key.h>
#include <common/tp_info.h>

#include <logger/bpf_dbg.h>

#include <maps/go_trace_map.h>
#include <maps/ongoing_goroutines.h>

#include <pid/pid_helpers.h>

static __always_inline void
go_addr_key_from_id_and_pid(go_addr_key_t *current, void *addr, const u32 pid) {
    current->addr = (u64)addr;
    current->pid = pid;
}

static __always_inline void go_addr_key_from_id(go_addr_key_t *current, void *addr) {
    const u64 pid_tid = bpf_get_current_pid_tgid();
    const u32 pid = pid_from_pid_tgid(pid_tid);

    go_addr_key_from_id_and_pid(current, addr, pid);
}

static __always_inline u64 find_parent_goroutine(go_addr_key_t *current) {
    if (!current) {
        return 0;
    }

    u64 r_addr = current->addr;
    go_addr_key_t *parent = current;

    int attempts = 0;
    do {
        tp_info_t *p_inv = bpf_map_lookup_elem(&go_trace_map, parent);
        if (!p_inv) { // not this goroutine running the server request processing
            // Let's find the parent scope
            goroutine_metadata *g_metadata =
                (goroutine_metadata *)bpf_map_lookup_elem(&ongoing_goroutines, parent);
            if (g_metadata) {
                // Lookup now to see if the parent was a request
                // Debug here commented out on purpose to avoid prints in loops.
                // bpf_printk("lookup %llx -> %llx", r_addr, g_metadata->parent.addr);
                r_addr = g_metadata->parent.addr;
                parent = &g_metadata->parent;
            } else {
                break;
            }
        } else {
            bpf_dbg_printk("Found parent, r_addr=%lx", r_addr);
            return r_addr;
        }

        attempts++;
        // We loop far back because some clients, e.g. Kafka Franz-Go really nest the
        // client calls.
    } while (attempts < 6); // Up to 6 levels of goroutine nesting allowed

    return 0;
}

static __always_inline u64 find_parent_goroutine_in_chain(go_addr_key_t *current) {
    if (!current) {
        return 0;
    }

    // Let's find the parent scope
    goroutine_metadata *g_metadata =
        (goroutine_metadata *)bpf_map_lookup_elem(&ongoing_goroutines, current);
    if (g_metadata) {
        // Lookup now to see if the parent was a request
        return g_metadata->parent.addr;
    }

    return 0;
}
