// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/utils.h>

#include <generictracer/jvm.h>
#include <common/event_defs.h>
#include <common/ringbuf.h>
#include <logger/bpf_dbg.h>
#include <pid/pid.h>
#include <common/usdt.h>

enum { k_jvm_task_comm_len = 16 };

struct jvm_mem_pool_gc_event _jvm_mem_pool_gc_event = {};

struct jvm_pid_fields {
    u32 global_pid;
    u32 global_tid;
    u32 ns_pid;
    u32 ns_tid;
    u32 pid_ns_id;
};

static __always_inline void jvm_current_pid_fields(u64 pid_tgid, struct jvm_pid_fields *fields) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;

    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    fields->global_pid = pid_from_pid_tgid(pid_tgid);
    fields->global_tid = tid_from_pid_tgid(pid_tgid);
    fields->ns_pid = (u32)ns_pid;
    fields->ns_tid = get_task_tid();
    fields->pid_ns_id = pid_ns_id;
}

static __always_inline void jvm_fill_mem_pool_pid_fields(u64 pid_tgid,
                                                         struct jvm_mem_pool_gc_event *e) {
    struct jvm_pid_fields fields = {};
    jvm_current_pid_fields(pid_tgid, &fields);

    e->global_pid = fields.global_pid;
    e->global_tid = fields.global_tid;
    e->ns_pid = fields.ns_pid;
    e->ns_tid = fields.ns_tid;
    e->pid_ns_id = fields.pid_ns_id;
}

static __always_inline int
jvm_read_usdt_string(unsigned char *dst, const unsigned char *src, long src_len) {
    bpf_memset(dst, 0, k_jvm_raw_string_len);
    if (!src || src_len <= 0) {
        return -1;
    }

    u32 max_len = (u32)src_len;
    bpf_clamp_umax(max_len, k_jvm_raw_string_len - 1);
    if (bpf_probe_read_user(dst, max_len, src) != 0) {
        return -1;
    }

    return 0;
}

static __always_inline int jvm_hotspot_mem_pool_gc(enum jvm_gc_when_type when,
                                                   u64 pid_tgid,
                                                   u32 pid,
                                                   const unsigned char *manager,
                                                   long manager_len,
                                                   const unsigned char *pool,
                                                   long pool_len,
                                                   u64 init_size,
                                                   u64 used,
                                                   u64 committed,
                                                   u64 max_size) {
    if (when != k_jvm_before_gc && when != k_jvm_after_gc) {
        return 0;
    }

    struct jvm_mem_pool_key key = {
        .pid = pid,
        .gc_when_type = when,
    };
    if (jvm_read_usdt_string(key.manager, manager, manager_len) != 0) {
        bpf_dbg_printk("jvm: failed to read HotSpot memory manager name len=%ld", manager_len);
        return 0;
    }
    if (jvm_read_usdt_string(key.pool, pool, pool_len) != 0) {
        bpf_dbg_printk("jvm: failed to read HotSpot memory pool name len=%ld", pool_len);
        return 0;
    }

    const u64 ts = bpf_ktime_get_ns();
    if (!jvm_should_sample_mem_pool(&key, ts)) {
        return 0;
    }

    struct jvm_mem_pool_gc_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    bpf_memset(e, 0, sizeof(*e));
    e->type = EVENT_JVM_MEM_POOL_GC;
    e->timestamp = ts;
    jvm_fill_mem_pool_pid_fields(pid_tgid, e);
    e->gc_when_type = when;
    e->init_size = init_size;
    e->used = used;
    e->committed = committed;
    e->max_size = max_size;
    bpf_memcpy(e->manager, key.manager, sizeof(e->manager));
    bpf_memcpy(e->pool, key.pool, sizeof(e->pool));

    bpf_ringbuf_submit(e, get_flags());
    return 0;
}

static __always_inline int
jvm_read_hotspot_usdt_arg(struct pt_regs *ctx, enum jvm_gc_when_type when, u64 arg_num, long *dst) {
    int err = obi_usdt_arg(ctx, arg_num, dst);
    if (err != 0) {
        const u64 pid_tgid = bpf_get_current_pid_tgid();
        struct jvm_pid_fields fields = {};
        jvm_current_pid_fields(pid_tgid, &fields);
        bpf_dbg_printk("jvm usdt ph=%d a=%llu e=%d", when, arg_num, err);
        bpf_dbg_printk(
            "jvm usdt gp=%d up=%d ns=%d", fields.global_pid, fields.ns_pid, fields.pid_ns_id);
        bpf_dbg_printk("jvm usdt ip=%llx", (u64)PT_REGS_IP(ctx));
    }
    return err;
}

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/services/memoryManager.cpp#L230
SEC("usdt/hotspot_mem_pool_gc_begin")
int obi_usdt_hotspot_mem_pool_gc_begin(struct pt_regs *ctx) {
    if (!jvm_runtime_metrics_are_enabled()) {
        return 0;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u32 pid = valid_pid(pid_tgid);
    if (!pid) {
        return 0;
    }

    long manager = 0;
    long manager_len = 0;
    long pool = 0;
    long pool_len = 0;
    long init_size = 0;
    long used = 0;
    long committed = 0;
    long max_size = 0;

    if (jvm_read_hotspot_usdt_arg(ctx, k_jvm_before_gc, 0, &manager) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_before_gc, 1, &manager_len) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_before_gc, 2, &pool) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_before_gc, 3, &pool_len) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_before_gc, 4, &init_size) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_before_gc, 5, &used) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_before_gc, 6, &committed) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_before_gc, 7, &max_size) != 0) {
        return 0;
    }

    return jvm_hotspot_mem_pool_gc(k_jvm_before_gc,
                                   pid_tgid,
                                   pid,
                                   (const unsigned char *)manager,
                                   manager_len,
                                   (const unsigned char *)pool,
                                   pool_len,
                                   (u64)init_size,
                                   (u64)used,
                                   (u64)committed,
                                   (u64)max_size);
}

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/services/memoryManager.cpp#L263
SEC("usdt/hotspot_mem_pool_gc_end")
int obi_usdt_hotspot_mem_pool_gc_end(struct pt_regs *ctx) {
    if (!jvm_runtime_metrics_are_enabled()) {
        return 0;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u32 pid = valid_pid(pid_tgid);
    if (!pid) {
        return 0;
    }

    long manager = 0;
    long manager_len = 0;
    long pool = 0;
    long pool_len = 0;
    long init_size = 0;
    long used = 0;
    long committed = 0;
    long max_size = 0;

    if (jvm_read_hotspot_usdt_arg(ctx, k_jvm_after_gc, 0, &manager) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_after_gc, 1, &manager_len) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_after_gc, 2, &pool) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_after_gc, 3, &pool_len) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_after_gc, 4, &init_size) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_after_gc, 5, &used) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_after_gc, 6, &committed) != 0 ||
        jvm_read_hotspot_usdt_arg(ctx, k_jvm_after_gc, 7, &max_size) != 0) {
        return 0;
    }

    return jvm_hotspot_mem_pool_gc(k_jvm_after_gc,
                                   pid_tgid,
                                   pid,
                                   (const unsigned char *)manager,
                                   manager_len,
                                   (const unsigned char *)pool,
                                   pool_len,
                                   (u64)init_size,
                                   (u64)used,
                                   (u64)committed,
                                   (u64)max_size);
}
