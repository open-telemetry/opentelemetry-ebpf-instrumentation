// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/utils.h>

#include <generictracer/jvm.h>
#include <generictracer/maps/jvm_gc_calls.h>
#include <common/event_defs.h>
#include <common/preempt_guard.h>
#include <common/ringbuf.h>
#include <logger/bpf_dbg.h>
#include <pid/pid.h>
#include <common/usdt.h>

enum { k_jvm_task_comm_len = 16 };

struct jvm_mem_pool_gc_event _jvm_mem_pool_gc_event = {};
struct jvm_runtime_metrics_event _jvm_runtime_metrics_event = {};
struct jvm_gc_duration_event _jvm_gc_duration_event = {};

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

static __always_inline int jvm_submit_mem_pool_gc(struct jvm_mem_pool_key *key,
                                                  u64 pid_tgid,
                                                  const struct hotspot_memory_usage *usage) {
    const u64 ts = bpf_ktime_get_ns();
    if (!jvm_should_sample_mem_pool(key, ts)) {
        return 0;
    }

    struct jvm_mem_pool_gc_event *e = events_ringbuf_reserve(sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    bpf_memset(e, 0, sizeof(*e));
    e->type = k_event_type_jvm_mem_pool_gc;
    e->timestamp = ts;
    jvm_fill_mem_pool_pid_fields(pid_tgid, e);
    e->gc_when_type = key->gc_when_type;
    e->init_size = usage->init_size;
    e->used = usage->used;
    e->committed = usage->committed;
    e->max_size = usage->max_size;
    bpf_memcpy(e->manager, key->manager, sizeof(e->manager));
    bpf_memcpy(e->pool, key->pool, sizeof(e->pool));

    bpf_ringbuf_submit(e, get_flags());
    return 0;
}

static __always_inline int jvm_hotspot_mem_pool_gc(enum jvm_gc_when_type when,
                                                   u64 pid_tgid,
                                                   u32 pid,
                                                   const unsigned char *manager,
                                                   long manager_len,
                                                   const unsigned char *pool,
                                                   long pool_len,
                                                   const struct hotspot_memory_usage *usage) {
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

    return jvm_submit_mem_pool_gc(&key, pid_tgid, usage);
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
int GUARDED_PROG(obi_usdt_hotspot_mem_pool_gc_begin, struct pt_regs *, ctx) {
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

    const struct hotspot_memory_usage usage = {
        .init_size = (u64)init_size,
        .used = (u64)used,
        .committed = (u64)committed,
        .max_size = (u64)max_size,
    };

    return jvm_hotspot_mem_pool_gc(k_jvm_before_gc,
                                   pid_tgid,
                                   pid,
                                   (const unsigned char *)manager,
                                   manager_len,
                                   (const unsigned char *)pool,
                                   pool_len,
                                   &usage);
}

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/services/memoryManager.cpp#L263
SEC("usdt/hotspot_mem_pool_gc_end")
int GUARDED_PROG(obi_usdt_hotspot_mem_pool_gc_end, struct pt_regs *, ctx) {
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

    const struct hotspot_memory_usage usage = {
        .init_size = (u64)init_size,
        .used = (u64)used,
        .committed = (u64)committed,
        .max_size = (u64)max_size,
    };

    return jvm_hotspot_mem_pool_gc(k_jvm_after_gc,
                                   pid_tgid,
                                   pid,
                                   (const unsigned char *)manager,
                                   manager_len,
                                   (const unsigned char *)pool,
                                   pool_len,
                                   &usage);
}

// The uprobes below stand in for the memory pool USDT probes on HotSpot builds
// that ship without them. They read the same MemoryPool::get_memory_usage()
// results the probes report, while GCMemoryManager::gc_begin or gc_end runs.
static __always_inline int jvm_gc_phase_enter(enum jvm_gc_when_type when, u64 manager_id) {
    if (!jvm_runtime_metrics_are_enabled()) {
        return 0;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u32 pid = valid_pid(pid_tgid);
    if (!pid) {
        return 0;
    }

    const struct jvm_gc_call call = {
        .manager_id = manager_id,
        .gc_when_type = when,
        .pid = pid,
    };
    bpf_map_update_elem(&jvm_gc_calls, &pid_tgid, &call, BPF_ANY);
    return 0;
}

static __always_inline int jvm_gc_phase_exit(void) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&jvm_gc_calls, &pid_tgid);
    return 0;
}

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/services/memoryManager.cpp#L212
SEC("uprobe/hotspot_gc_begin")
int GUARDED_PROG(obi_uprobe_hotspot_gc_begin, struct pt_regs *, ctx) {
    return jvm_gc_phase_enter(k_jvm_before_gc, (u64)PT_REGS_PARM1(ctx));
}

SEC("uretprobe/hotspot_gc_begin")
int GUARDED_PROG(obi_uretprobe_hotspot_gc_begin, struct pt_regs *, ctx) {
    (void)ctx;
    return jvm_gc_phase_exit();
}

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/services/memoryManager.cpp#L242
SEC("uprobe/hotspot_gc_end")
int GUARDED_PROG(obi_uprobe_hotspot_gc_end, struct pt_regs *, ctx) {
    return jvm_gc_phase_enter(k_jvm_after_gc, (u64)PT_REGS_PARM1(ctx));
}

SEC("uretprobe/hotspot_gc_end")
int GUARDED_PROG(obi_uretprobe_hotspot_gc_end, struct pt_regs *, ctx) {
    (void)ctx;
    return jvm_gc_phase_exit();
}

// MemoryPool::get_memory_usage() returns its MemoryUsage through a hidden
// result pointer: x86-64 passes it in RDI ahead of `this`, arm64 passes it in X8.
static __always_inline void
jvm_memory_pool_usage_args(const struct pt_regs *ctx, u64 *pool, u64 *usage) {
#ifdef __TARGET_ARCH_x86
    *usage = (u64)PT_REGS_PARM1(ctx);
    *pool = (u64)PT_REGS_PARM2(ctx);
#elif defined(__TARGET_ARCH_arm64)
    *pool = (u64)PT_REGS_PARM1(ctx);
    *usage = ((PT_REGS_ARM64 *)ctx)->regs[8];
#endif
}

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/services/memoryPool.hpp#L135
SEC("uprobe/hotspot_memory_pool_usage")
int GUARDED_PROG(obi_uprobe_hotspot_memory_pool_usage, struct pt_regs *, ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    struct jvm_gc_call *call = bpf_map_lookup_elem(&jvm_gc_calls, &pid_tgid);
    if (!call) {
        return 0;
    }

    jvm_memory_pool_usage_args(ctx, &call->pool, &call->usage);
    return 0;
}

SEC("uretprobe/hotspot_memory_pool_usage")
int GUARDED_PROG(obi_uretprobe_hotspot_memory_pool_usage, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    struct jvm_gc_call *call = bpf_map_lookup_elem(&jvm_gc_calls, &pid_tgid);
    if (!call || !call->pool || !call->usage) {
        return 0;
    }

    const struct hotspot_memory_pool *pool = (const struct hotspot_memory_pool *)call->pool;
    const struct hotspot_memory_usage *usage_ptr = (const struct hotspot_memory_usage *)call->usage;
    call->pool = 0;
    call->usage = 0;

    struct hotspot_memory_usage usage = {};
    if (bpf_probe_read_user(&usage, sizeof(usage), usage_ptr) != 0) {
        bpf_dbg_printk("jvm: failed to read HotSpot MemoryUsage at %llx", (u64)usage_ptr);
        return 0;
    }

    u64 name = 0;
    if (bpf_probe_read_user(&name, sizeof(name), &pool->name) != 0 || !name) {
        return 0;
    }

    struct jvm_mem_pool_key key = {
        .manager_id = call->manager_id,
        .pid = call->pid,
        .gc_when_type = call->gc_when_type,
    };
    if (bpf_probe_read_user_str(key.pool, sizeof(key.pool), (const void *)name) <= 0) {
        bpf_dbg_printk("jvm: failed to read HotSpot MemoryPool name at %llx", name);
        return 0;
    }

    return jvm_submit_mem_pool_gc(&key, pid_tgid, &usage);
}
