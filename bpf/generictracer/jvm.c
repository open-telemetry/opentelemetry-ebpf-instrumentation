// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <generictracer/jvm.h>
#include <logger/bpf_dbg.h>
#include <pid/pid.h>

enum { k_jvm_task_comm_len = 16 };

struct jvm_gc_heap_summary_event _jvm_gc_heap_summary_event = {};

static __always_inline bool jvm_current_comm_is_g1_main_marker(void) {
    char comm[k_jvm_task_comm_len] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    const char g1_main_marker[] = "G1 Main Marker";
    return __builtin_memcmp(comm, g1_main_marker, sizeof(g1_main_marker)) == 0;
}

static __always_inline void jvm_fill_heap_pid_fields(u64 pid_tgid, struct jvm_gc_heap_summary_event *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;

    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    e->global_pid = pid_from_pid_tgid(pid_tgid);
    e->global_tid = tid_from_pid_tgid(pid_tgid);
    e->ns_pid = (u32)ns_pid;
    e->ns_tid = get_task_tid();
}

SEC("uprobe/report_gc_heap_summary")
int BPF_UPROBE(obi_uprobe_report_gc_heap_summary,
               void *clazz,
               enum jvm_gc_when_type when,
               struct jvm_gc_heap_summary *summary) {
    (void)clazz;

    if (!jvm_runtime_metrics_enabled) {
        return 0;
    }

    if (jvm_current_comm_is_g1_main_marker()) {
        return 0;
    }

    if (when != k_jvm_before_gc && when != k_jvm_after_gc) {
        return 0;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u32 pid = valid_pid(pid_tgid);
    if (!pid) {
        return 0;
    }

    const u64 ts = bpf_ktime_get_ns();
    struct jvm_heap_summary_key key = {
        .pid = pid,
        .gc_when_type = when,
    };

    if (!jvm_should_sample_heap_summary(&key, ts)) {
        return 0;
    }

    u64 used = 0;
    if (bpf_probe_read_user(&used, sizeof(used), &summary->used) != 0) {
        bpf_dbg_printk("jvm: failed to read GCHeapSummary.used");
        return 0;
    }

    struct jvm_gc_heap_summary_event *e = bpf_ringbuf_reserve(&jvm_gc_heap_summary_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp = ts;
    jvm_fill_heap_pid_fields(pid_tgid, e);
    e->gc_when_type = when;
    e->used = used;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
