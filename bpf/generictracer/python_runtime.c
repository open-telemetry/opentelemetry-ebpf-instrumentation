// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/preempt_guard.h>
#include <common/ringbuf.h>
#include <generictracer/maps/python_runtime_metrics.h>
#include <logger/bpf_dbg.h>

#include <pid/pid.h>

enum {
    k_python_gc_generations = 3,
};

static __always_inline bool python_runtime_read(void *dst, u32 size, u64 address) {
    return address && bpf_probe_read_user(dst, size, (void *)address) == 0;
}

static __always_inline bool
python_runtime_read_counters(u64 address, struct python_gc_generation_metrics *metrics) {
    if (!python_runtime_read(metrics, sizeof(*metrics), address)) {
        return false;
    }

    return (s64)metrics->collections >= 0 && (s64)metrics->collected >= 0 &&
           (s64)metrics->uncollectable >= 0;
}

static __always_inline bool
python_runtime_read_inline(u64 gc_address,
                           const struct python_runtime_metric_target *target,
                           struct python_runtime_metric_snapshot *snapshot) {
    u64 stats_address = gc_address + target->gc_generation_stats;

    for (u32 generation = 0; generation < k_python_gc_generations; generation++) {
        if (!python_runtime_read_counters(
                stats_address + (generation * sizeof(struct python_gc_generation_metrics)),
                &snapshot->generations[generation])) {
            return false;
        }
    }
    return true;
}

SEC("uprobe/python_gc_done")
int GUARDED_PROG(obi_uprobe_python_gc_done, struct pt_regs *, ctx) {
    (void)ctx;

    pid_info key = {};
    task_pid(&key);

    bpf_dbg_printk("python GC probe pid=%d ns=%d", key.user_pid, key.ns);

    const struct python_runtime_metric_target *target =
        bpf_map_lookup_elem(&python_runtime_metric_targets, &key);
    if (!target || !target->runtime_addr) {
        bpf_dbg_printk("python GC target missing pid=%d ns=%d", key.user_pid, key.ns);
        return 0;
    }

    // CPython can tear down interpreter-owned GC state after finalization starts.
    u64 finalizing = 0;
    if (!python_runtime_read(
            &finalizing, sizeof(finalizing), target->runtime_addr + target->runtime_finalizing)) {
        bpf_dbg_printk("python GC finalizing read failed pid=%d ns=%d", key.user_pid, key.ns);
        return 0;
    }
    if (finalizing) {
        bpf_dbg_printk("python GC finalizing pid=%d ns=%d", key.user_pid, key.ns);
        return 0;
    }

    // OBI reports GC counters from the main interpreter only.
    u64 interpreter = 0;
    if (!python_runtime_read(&interpreter,
                             sizeof(interpreter),
                             target->runtime_addr + target->runtime_interpreters_main)) {
        bpf_dbg_printk("python GC interpreter read failed pid=%d ns=%d", key.user_pid, key.ns);
        return 0;
    }
    if (!interpreter) {
        bpf_dbg_printk("python GC interpreter missing pid=%d ns=%d", key.user_pid, key.ns);
        return 0;
    }

    struct python_runtime_metric_snapshot snapshot = {.generation = target->generation};
    const u64 gc_address = interpreter + target->interpreter_gc;
    if (!python_runtime_read_inline(gc_address, target, &snapshot)) {
        bpf_dbg_printk("python GC counters read failed pid=%d ns=%d", key.user_pid, key.ns);
        return 0;
    }

    // Keep the latest snapshot for process exit, even if ring-buffer reservation fails.
    if (bpf_map_update_elem(&python_runtime_metric_snapshots, &key, &snapshot, BPF_ANY) != 0) {
        bpf_dbg_printk("python GC snapshot update failed pid=%d ns=%d", key.user_pid, key.ns);
    }

    struct python_runtime_metric_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_dbg_printk("python GC event reserve failed pid=%d ns=%d", key.user_pid, key.ns);
        return 0;
    }
    event->type = k_event_type_python_runtime_metrics;
    event->pid = key;
    event->snapshot = snapshot;
    bpf_ringbuf_submit(event, get_flags());

    bpf_dbg_printk("python GC snapshot pid=%d collections=%llu",
                   key.user_pid,
                   snapshot.generations[0].collections);

    return 0;
}
