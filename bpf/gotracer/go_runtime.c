// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build obi_bpf_ignore

#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/ringbuf.h>
#include <common/trace_helpers.h>

#include <gotracer/go_common.h>

#include <gotracer/maps/grpc.h>
#include <gotracer/maps/kafka.h>
#include <gotracer/maps/mongo.h>
#include <gotracer/maps/nethttp.h>
#include <gotracer/maps/redis.h>
#include <gotracer/maps/runtime.h>

#include <gotracer/types/grpc.h>
#include <gotracer/types/nethttp.h>

#include <logger/bpf_dbg.h>

#include <maps/go_ongoing_http_client_requests.h>

#include <pid/pid_helpers.h>

#include <shared/obi_ctx.h>

typedef struct new_func_invocation {
    u64 parent;
} new_func_invocation_t;

enum : u32 {
    k_go_runtime_heap_stats_slots = 3,
    k_go_runtime_heap_stats_fields_between_size_class_arrays = 2,
    k_go_runtime_max_size_classes = 68,
};

static __always_inline bool go_runtime_read(void *dst, u32 size, u64 addr) {
    if (!addr) {
        return false;
    }

    return bpf_probe_read_user(dst, size, (void *)addr) == 0;
}

static __always_inline bool go_runtime_read_offset(void *dst, u32 size, u64 base, u64 offset) {
    if (!base) {
        return false;
    }

    return go_runtime_read(dst, size, base + offset);
}

static __always_inline void go_runtime_collect_gc(const go_runtime_metric_target_t *target,
                                                  off_table_t *ot,
                                                  go_runtime_metric_snapshot_t *snapshot) {
    if (!(target->available_mask & go_runtime_metric_valid_gc_cycles)) {
        return;
    }

    const u64 num_gc_pos = go_offset_of(ot, (go_offset){.v = _runtime_memstats_numgc_pos});

    if (go_runtime_read_offset(
            &snapshot->num_gc, sizeof(snapshot->num_gc), target->memstats_addr, num_gc_pos)) {
        snapshot->valid_mask |= go_runtime_metric_valid_gc_cycles;
    }
}

static __always_inline void
go_runtime_collect_memory_config(const go_runtime_metric_target_t *target,
                                 off_table_t *ot,
                                 go_runtime_metric_snapshot_t *snapshot) {
    if (target->available_mask & go_runtime_metric_valid_gogc) {
        const u64 gc_percent_pos =
            go_offset_of(ot, (go_offset){.v = _runtime_gc_controller_gc_percent_pos});

        if (go_runtime_read_offset(&snapshot->gc_percent,
                                   sizeof(snapshot->gc_percent),
                                   target->gc_controller_addr,
                                   gc_percent_pos)) {
            snapshot->valid_mask |= go_runtime_metric_valid_gogc;
        }
    }

    if (target->available_mask & go_runtime_metric_valid_memory_limit) {
        const u64 memory_limit_pos =
            go_offset_of(ot, (go_offset){.v = _runtime_gc_controller_memory_limit_pos});

        if (go_runtime_read_offset(&snapshot->memory_limit,
                                   sizeof(snapshot->memory_limit),
                                   target->gc_controller_addr,
                                   memory_limit_pos)) {
            snapshot->valid_mask |= go_runtime_metric_valid_memory_limit;
        }
    }
}

static __always_inline void
go_runtime_collect_scheduler_config(const go_runtime_metric_target_t *target,
                                    go_runtime_metric_snapshot_t *snapshot) {
    if (!(target->available_mask & go_runtime_metric_valid_processor_limit)) {
        return;
    }

    if (go_runtime_read(
            &snapshot->gomaxprocs, sizeof(snapshot->gomaxprocs), target->gomaxprocs_addr)) {
        snapshot->valid_mask |= go_runtime_metric_valid_processor_limit;
    }
}

static __always_inline void go_runtime_collect_cpu_time(const go_runtime_metric_target_t *target,
                                                        off_table_t *ot,
                                                        go_runtime_metric_snapshot_t *snapshot) {
    if (!(target->available_mask & go_runtime_metric_valid_cpu_time) || !target->work_addr) {
        return;
    }

    const u64 cpu_stats_addr =
        target->work_addr + go_offset_of(ot, (go_offset){.v = _runtime_work_cpu_stats_pos});

    if (!go_runtime_read_offset(
            &snapshot->cpu_gc_assist_time,
            sizeof(snapshot->cpu_gc_assist_time),
            cpu_stats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_cpu_stats_gc_assist_time_pos}))) {
        return;
    }
    if (!go_runtime_read_offset(
            &snapshot->cpu_gc_dedicated_time,
            sizeof(snapshot->cpu_gc_dedicated_time),
            cpu_stats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_cpu_stats_gc_dedicated_time_pos}))) {
        return;
    }
    if (!go_runtime_read_offset(
            &snapshot->cpu_gc_idle_time,
            sizeof(snapshot->cpu_gc_idle_time),
            cpu_stats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_cpu_stats_gc_idle_time_pos}))) {
        return;
    }
    if (!go_runtime_read_offset(
            &snapshot->cpu_gc_pause_time,
            sizeof(snapshot->cpu_gc_pause_time),
            cpu_stats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_cpu_stats_gc_pause_time_pos}))) {
        return;
    }
    if (!go_runtime_read_offset(
            &snapshot->cpu_scavenge_assist_time,
            sizeof(snapshot->cpu_scavenge_assist_time),
            cpu_stats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_cpu_stats_scavenge_assist_time_pos}))) {
        return;
    }
    if (!go_runtime_read_offset(
            &snapshot->cpu_scavenge_bg_time,
            sizeof(snapshot->cpu_scavenge_bg_time),
            cpu_stats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_cpu_stats_scavenge_bg_time_pos}))) {
        return;
    }
    if (!go_runtime_read_offset(
            &snapshot->cpu_idle_time,
            sizeof(snapshot->cpu_idle_time),
            cpu_stats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_cpu_stats_idle_time_pos}))) {
        return;
    }
    if (!go_runtime_read_offset(
            &snapshot->cpu_user_time,
            sizeof(snapshot->cpu_user_time),
            cpu_stats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_cpu_stats_user_time_pos}))) {
        return;
    }

    snapshot->valid_mask |= go_runtime_metric_valid_cpu_time;
}

typedef struct go_runtime_heap_stats_totals {
    s64 committed;
    s64 in_stacks;
    u64 allocated;
    u64 allocations;
    u64 valid_mask;
} go_runtime_heap_stats_totals_t;

static __always_inline void
go_runtime_collect_heap_stats_totals(const go_runtime_metric_target_t *target,
                                     off_table_t *ot,
                                     const pid_info *pid,
                                     bool collect_memory_used,
                                     bool collect_memory_allocations,
                                     go_runtime_heap_stats_totals_t *totals) {
    const u64 heap_stats_pos = go_offset_of(ot, (go_offset){.v = _runtime_memstats_heap_stats_pos});
    const u64 stats_pos =
        go_offset_of(ot, (go_offset){.v = _runtime_consistent_heap_stats_stats_pos});
    const u64 committed_pos =
        go_offset_of(ot, (go_offset){.v = _runtime_heap_stats_delta_committed_pos});
    const u64 in_stacks_pos =
        go_offset_of(ot, (go_offset){.v = _runtime_heap_stats_delta_in_stacks_pos});
    const u64 large_alloc_pos =
        go_offset_of(ot, (go_offset){.v = _runtime_heap_stats_delta_large_alloc_pos});
    const u64 large_alloc_count_pos =
        go_offset_of(ot, (go_offset){.v = _runtime_heap_stats_delta_large_alloc_count_pos});
    const u64 small_alloc_count_pos =
        go_offset_of(ot, (go_offset){.v = _runtime_heap_stats_delta_small_alloc_count_pos});
    const u64 small_free_count_pos =
        go_offset_of(ot, (go_offset){.v = _runtime_heap_stats_delta_small_free_count_pos});
    const u64 stats_addr = target->memstats_addr + heap_stats_pos + stats_pos;

    if (small_alloc_count_pos % sizeof(u64) || small_free_count_pos % sizeof(u64) ||
        small_free_count_pos <= small_alloc_count_pos) {
        bpf_dbg_printk("invalid Go runtime size-class layout pid=%d ns=%d", pid->user_pid, pid->ns);
        return;
    }

    const u64 size_class_arrays_gap = small_free_count_pos - small_alloc_count_pos;
    // largeFree and largeFreeCount are the two u64 fields between the size-class arrays.
    const u64 intervening_fields_size =
        k_go_runtime_heap_stats_fields_between_size_class_arrays * sizeof(u64);
    if (size_class_arrays_gap <= intervening_fields_size ||
        (size_class_arrays_gap - intervening_fields_size) % sizeof(u64)) {
        bpf_dbg_printk(
            "invalid Go runtime size-class array gap pid=%d ns=%d", pid->user_pid, pid->ns);
        return;
    }

    const u64 size_class_counts_size = size_class_arrays_gap - intervening_fields_size;
    const u64 derived_size_class_count = size_class_counts_size / sizeof(u64);
    if (!derived_size_class_count || derived_size_class_count > k_go_runtime_max_size_classes ||
        small_free_count_pos + size_class_counts_size < small_free_count_pos) {
        bpf_dbg_printk(
            "unsupported Go runtime size-class layout pid=%d ns=%d", pid->user_pid, pid->ns);
        return;
    }
    const u32 size_class_count = (u32)derived_size_class_count;

    // heapStatsDelta ends with a second size-class array of the derived length.
    const u64 heap_stats_delta_size = small_free_count_pos + size_class_counts_size;

    s64 committed = 0;
    s64 in_stacks = 0;
    u64 allocated = 0;
    u64 allocations = 0;

    if (collect_memory_used) {
        totals->valid_mask |= go_runtime_metric_valid_memory_used;
    }
    if (collect_memory_allocations) {
        totals->valid_mask |= go_runtime_metric_valid_memory_allocations;
    }

    // nextGen runs stop-the-world, so the three rotating slots form one consistent snapshot.
    for (u32 slot = 0; slot < k_go_runtime_heap_stats_slots; slot++) {
        const u64 slot_addr = stats_addr + (slot * heap_stats_delta_size);

        if (totals->valid_mask & go_runtime_metric_valid_memory_used) {
            s64 slot_committed = 0;
            s64 slot_in_stacks = 0;
            if (!go_runtime_read_offset(
                    &slot_committed, sizeof(slot_committed), slot_addr, committed_pos)) {
                totals->valid_mask &= ~go_runtime_metric_valid_memory_used;
            } else if (!go_runtime_read_offset(
                           &slot_in_stacks, sizeof(slot_in_stacks), slot_addr, in_stacks_pos)) {
                totals->valid_mask &= ~go_runtime_metric_valid_memory_used;
            } else {
                committed += slot_committed;
                in_stacks += slot_in_stacks;
            }
        }

        if (totals->valid_mask & go_runtime_metric_valid_memory_allocations) {
            u64 slot_large_alloc = 0;
            u64 slot_large_alloc_count = 0;
            if (!go_runtime_read_offset(
                    &slot_large_alloc, sizeof(slot_large_alloc), slot_addr, large_alloc_pos)) {
                totals->valid_mask &= ~go_runtime_metric_valid_memory_allocations;
            } else if (!go_runtime_read_offset(&slot_large_alloc_count,
                                               sizeof(slot_large_alloc_count),
                                               slot_addr,
                                               large_alloc_count_pos)) {
                totals->valid_mask &= ~go_runtime_metric_valid_memory_allocations;
            } else {
                allocated += slot_large_alloc;
                allocations += slot_large_alloc_count;
            }
        }
    }

    if (totals->valid_mask & go_runtime_metric_valid_memory_allocations) {
        // Go's heap allocation metrics deliberately exclude tiny allocations.
        for (u32 size_class = 0; size_class < k_go_runtime_max_size_classes; size_class++) {
            if (size_class >= size_class_count) {
                break;
            }

            u16 class_size = 0;
            if (!go_runtime_read(&class_size,
                                 sizeof(class_size),
                                 target->size_class_to_sizes_addr +
                                     (size_class * sizeof(class_size)))) {
                totals->valid_mask &= ~go_runtime_metric_valid_memory_allocations;
                break;
            }

            for (u32 slot = 0; slot < k_go_runtime_heap_stats_slots; slot++) {
                const u64 slot_addr = stats_addr + (slot * heap_stats_delta_size);
                u64 small_alloc_count = 0;
                if (!go_runtime_read_offset(&small_alloc_count,
                                            sizeof(small_alloc_count),
                                            slot_addr,
                                            small_alloc_count_pos +
                                                (size_class * sizeof(small_alloc_count)))) {
                    totals->valid_mask &= ~go_runtime_metric_valid_memory_allocations;
                    break;
                }
                allocated += small_alloc_count * class_size;
                allocations += small_alloc_count;
            }
            if (!(totals->valid_mask & go_runtime_metric_valid_memory_allocations)) {
                break;
            }
        }
    }

    if (collect_memory_used && !(totals->valid_mask & go_runtime_metric_valid_memory_used)) {
        bpf_dbg_printk(
            "can't read Go runtime memory-used heap stats pid=%d ns=%d", pid->user_pid, pid->ns);
    }
    if (collect_memory_allocations &&
        !(totals->valid_mask & go_runtime_metric_valid_memory_allocations)) {
        bpf_dbg_printk(
            "can't read Go runtime allocation heap stats pid=%d ns=%d", pid->user_pid, pid->ns);
    }

    totals->committed = committed;
    totals->in_stacks = in_stacks;
    totals->allocated = allocated;
    totals->allocations = allocations;
}

static __always_inline void go_runtime_collect_heap_stats(const go_runtime_metric_target_t *target,
                                                          off_table_t *ot,
                                                          const pid_info *pid,
                                                          go_runtime_metric_snapshot_t *snapshot) {
    const bool collect_memory_used = target->available_mask & go_runtime_metric_valid_memory_used;
    const bool collect_memory_allocations =
        (target->available_mask & go_runtime_metric_valid_memory_allocations) &&
        target->size_class_to_sizes_addr;
    if (!collect_memory_used && !collect_memory_allocations) {
        return;
    }

    go_runtime_heap_stats_totals_t totals = {};
    go_runtime_collect_heap_stats_totals(
        target, ot, pid, collect_memory_used, collect_memory_allocations, &totals);

    if (totals.valid_mask & go_runtime_metric_valid_memory_allocations) {
        snapshot->memory_allocated = totals.allocated;
        snapshot->memory_allocations = totals.allocations;
        snapshot->valid_mask |= go_runtime_metric_valid_memory_allocations;
    }
    if (!(totals.valid_mask & go_runtime_metric_valid_memory_used)) {
        return;
    }

    u64 stacks_sys = 0;
    u64 mspan_sys = 0;
    u64 mcache_sys = 0;
    u64 buckhash_sys = 0;
    u64 gc_misc_sys = 0;
    u64 other_sys = 0;
    if (!go_runtime_read_offset(
            &stacks_sys,
            sizeof(stacks_sys),
            target->memstats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_memstats_stacks_sys_pos}))) {
        bpf_dbg_printk("can't read Go runtime stacks_sys pid=%d ns=%d", pid->user_pid, pid->ns);
        return;
    }
    if (!go_runtime_read_offset(
            &mspan_sys,
            sizeof(mspan_sys),
            target->memstats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_memstats_mspan_sys_pos}))) {
        bpf_dbg_printk("can't read Go runtime mspan_sys pid=%d ns=%d", pid->user_pid, pid->ns);
        return;
    }
    if (!go_runtime_read_offset(
            &mcache_sys,
            sizeof(mcache_sys),
            target->memstats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_memstats_mcache_sys_pos}))) {
        bpf_dbg_printk("can't read Go runtime mcache_sys pid=%d ns=%d", pid->user_pid, pid->ns);
        return;
    }
    if (!go_runtime_read_offset(
            &buckhash_sys,
            sizeof(buckhash_sys),
            target->memstats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_memstats_buckhash_sys_pos}))) {
        bpf_dbg_printk("can't read Go runtime buckhash_sys pid=%d ns=%d", pid->user_pid, pid->ns);
        return;
    }
    if (!go_runtime_read_offset(
            &gc_misc_sys,
            sizeof(gc_misc_sys),
            target->memstats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_memstats_gc_misc_sys_pos}))) {
        bpf_dbg_printk("can't read Go runtime gc_misc_sys pid=%d ns=%d", pid->user_pid, pid->ns);
        return;
    }
    if (!go_runtime_read_offset(
            &other_sys,
            sizeof(other_sys),
            target->memstats_addr,
            go_offset_of(ot, (go_offset){.v = _runtime_memstats_other_sys_pos}))) {
        bpf_dbg_printk("can't read Go runtime other_sys pid=%d ns=%d", pid->user_pid, pid->ns);
        return;
    }

    const s64 sys_other =
        (s64)(stacks_sys + mspan_sys + mcache_sys + buckhash_sys + gc_misc_sys + other_sys);
    snapshot->memory_used_stack = totals.in_stacks;
    // This is the runtime/metrics identity: committed - inStacks + non-heap Sys fields.
    snapshot->memory_used_other = totals.committed - totals.in_stacks + sys_other;
    snapshot->valid_mask |= go_runtime_metric_valid_memory_used;
}

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, new_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} newproc1 SEC(".maps");

SEC("uprobe/go_runtime_metrics")
int obi_uprobe_go_runtime_metrics(struct pt_regs *ctx) {
    (void)ctx;

    pid_info key = {};
    task_pid(&key);

    bpf_dbg_printk("collecting Go runtime metrics pid=%d ns=%d", key.user_pid, key.ns);

    const go_runtime_metric_target_t *target =
        bpf_map_lookup_elem(&go_runtime_metric_targets, &key);
    if (!target) {
        return 0;
    }

    go_runtime_metric_event_t *event =
        bpf_ringbuf_reserve(&events, sizeof(go_runtime_metric_event_t), 0);
    if (!event) {
        return 0;
    }

    event->type = EVENT_GO_RUNTIME_METRICS;
    event->pid = key;
    // Collectors set valid_mask bits for metric groups populated in this snapshot.
    __builtin_memset(&event->snapshot, 0, sizeof(event->snapshot));

    off_table_t *ot = get_offsets_table();
    go_runtime_collect_gc(target, ot, &event->snapshot);
    go_runtime_collect_memory_config(target, ot, &event->snapshot);
    go_runtime_collect_scheduler_config(target, &event->snapshot);
    go_runtime_collect_cpu_time(target, ot, &event->snapshot);
    go_runtime_collect_heap_stats(target, ot, &key, &event->snapshot);

    bpf_ringbuf_submit(event, get_flags());
    return 0;
}

SEC("uprobe/runtime_newproc1")
int obi_uprobe_runtime_newproc1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/runtime_newproc1 ===");
    void *creator_goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr=%lx", creator_goroutine_addr);

    new_func_invocation_t invocation = {.parent = (u64)GO_PARAM2(ctx)};
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, creator_goroutine_addr);

    // Save the registers on invocation to be able to fetch the arguments at return of newproc1
    if (bpf_map_update_elem(&newproc1, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/runtime_newproc1_return")
int obi_uprobe_runtime_newproc1_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/runtime_newproc1_return ===");
    void *creator_goroutine_addr = GOROUTINE_PTR(ctx);
    const u64 pid_tid = bpf_get_current_pid_tgid();
    const u32 pid = pid_from_pid_tgid(pid_tid);
    go_addr_key_t c_key = {.addr = (u64)creator_goroutine_addr, .pid = pid};

    bpf_dbg_printk("creator_goroutine_addr=%lx", creator_goroutine_addr);

    // Lookup the newproc1 invocation metadata
    new_func_invocation_t *invocation = bpf_map_lookup_elem(&newproc1, &c_key);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read newproc1 invocation metadata");
        goto done;
    }

    // The parent goroutine is the second argument of newproc1
    void *parent_goroutine = (void *)invocation->parent;
    bpf_dbg_printk("parent_goroutine=%lx", parent_goroutine);

    // The result of newproc1 is the new goroutine
    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t p_key = {.addr = (u64)parent_goroutine, .pid = pid};

    goroutine_metadata *g_metadata =
        (goroutine_metadata *)bpf_map_lookup_elem(&ongoing_goroutines, &p_key);

    if (g_metadata) {
        // Don't create cycles at one level on immediate goroutine reuse
        if (g_metadata->parent.addr == (u64)goroutine_addr) {
            bpf_dbg_printk("avoiding cycle %llx -> %llx", parent_goroutine, goroutine_addr);
            goto done;
        }
    }

    go_addr_key_t g_key = {.addr = (u64)goroutine_addr, .pid = pid};

    goroutine_metadata metadata = {
        .timestamp = bpf_ktime_get_ns(),
        .parent = p_key,
    };

    if (bpf_map_update_elem(&ongoing_goroutines, &g_key, &metadata, BPF_ANY)) {
        bpf_dbg_printk("can't update active goroutine");
    }

done:
    bpf_map_delete_elem(&newproc1, &c_key);

    return 0;
}

static __always_inline bool valid_tp_info(const tp_info_t *tp) {
    return tp && valid_trace(tp->trace_id) && valid_span(tp->span_id);
}

static __always_inline bool current_obi_handoff(struct pt_regs *ctx, chan_handoff_t *handoff) {
    if (!handoff) {
        return false;
    }

    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_srv_func_invocation_t *grpc_server_inv =
        bpf_map_lookup_elem(&ongoing_grpc_server_requests, &g_key);
    if (grpc_server_inv && valid_tp_info(&grpc_server_inv->tp)) {
        tp_clone(&handoff->tp, &grpc_server_inv->tp);
        return true;
    }

    grpc_client_func_invocation_t *grpc_client_inv =
        bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);
    if (grpc_client_inv && valid_tp_info(&grpc_client_inv->tp)) {
        tp_clone(&handoff->tp, &grpc_client_inv->tp);
        return true;
    }

    server_http_func_invocation_t *http_server_inv =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);
    if (http_server_inv && valid_tp_info(&http_server_inv->tp)) {
        tp_clone(&handoff->tp, &http_server_inv->tp);
        return true;
    }

    http_func_invocation_t *http_client_inv =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);
    if (http_client_inv && valid_tp_info(&http_client_inv->tp)) {
        tp_clone(&handoff->tp, &http_client_inv->tp);
        return true;
    }

    tp_info_t *kafka_go_tp = bpf_map_lookup_elem(&produce_traceparents_by_goroutine, &g_key);
    if (valid_tp_info(kafka_go_tp)) {
        tp_clone(&handoff->tp, kafka_go_tp);
        return true;
    }

    mongo_go_client_req_t *mongo = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    if (mongo && valid_tp_info(&mongo->tp)) {
        tp_clone(&handoff->tp, &mongo->tp);
        return true;
    }

    redis_client_req_t *redis = bpf_map_lookup_elem(&ongoing_redis_requests, &g_key);
    if (redis && valid_tp_info(&redis->tp)) {
        tp_clone(&handoff->tp, &redis->tp);
        return true;
    }

    sql_func_invocation_t *sql = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
    if (sql && valid_tp_info(&sql->tp)) {
        tp_clone(&handoff->tp, &sql->tp);
        return true;
    }

    obi_ctx_info_t *obi_ctx = obi_ctx__get(bpf_get_current_pid_tgid());
    if (obi_ctx && valid_trace(obi_ctx->trace_id) && valid_span(obi_ctx->span_id)) {
        __builtin_memcpy(handoff->tp.trace_id, obi_ctx->trace_id, sizeof(handoff->tp.trace_id));
        __builtin_memcpy(handoff->tp.span_id, obi_ctx->span_id, sizeof(handoff->tp.span_id));
        *((u64 *)handoff->tp.parent_id) = 0;
        handoff->tp.flags = 0;
        return true;
    }

    return false;
}

static __always_inline bool same_span_context(const tp_info_t *a, const tp_info_t *b) {
    if (!a || !b) {
        return false;
    }

    return *((u64 *)a->span_id) == *((u64 *)b->span_id) &&
           *((u64 *)a->trace_id) == *((u64 *)b->trace_id) &&
           *((u64 *)(a->trace_id + 8)) == *((u64 *)(b->trace_id + 8));
}

static __always_inline void emit_channel_handoff(chan_handoff_t *sender, chan_handoff_t *receiver) {
    if (!sender || !receiver || !valid_tp_info(&sender->tp) || !valid_tp_info(&receiver->tp)) {
        return;
    }

    if (same_span_context(&sender->tp, &receiver->tp)) {
        return;
    }

    channel_link_trace_t *trace = bpf_ringbuf_reserve(&events, sizeof(*trace), 0);
    if (!trace) {
        return;
    }

    trace->type = EVENT_GO_CHANNEL_LINK;
    tp_clone(&trace->sender_tp, &sender->tp);
    tp_clone(&trace->receiver_tp, &receiver->tp);
    bpf_ringbuf_submit(trace, get_flags());
}

static __always_inline bool
read_channel_u64(const void *chan_ptr, go_offset_const field, u64 *value) {
    if (!chan_ptr || !value) {
        return false;
    }

    off_table_t *ot = get_offsets_table();
    const u64 offset = go_offset_of(ot, (go_offset){.v = field});
    if (offset == (u64)-1) {
        return false;
    }

    return bpf_probe_read_user(value, sizeof(*value), chan_ptr + offset) == 0;
}

static __always_inline bool read_channel_qcount(const void *chan_ptr, u64 *qcount) {
    return read_channel_u64(chan_ptr, _hchan_qcount_pos, qcount);
}

static __always_inline bool read_channel_dataqsiz(const void *chan_ptr, u64 *dataqsiz) {
    return read_channel_u64(chan_ptr, _hchan_dataqsiz_pos, dataqsiz);
}

static __always_inline bool read_channel_sendx(const void *chan_ptr, u64 *sendx) {
    return read_channel_u64(chan_ptr, _hchan_sendx_pos, sendx);
}

static __always_inline bool read_channel_recvx(const void *chan_ptr, u64 *recvx) {
    return read_channel_u64(chan_ptr, _hchan_recvx_pos, recvx);
}

static __always_inline u64 previous_channel_slot(u64 index, u64 dataqsiz) {
    if (dataqsiz == 0) {
        return 0;
    }

    return index == 0 ? dataqsiz - 1 : index - 1;
}

static __always_inline void record_direct_channel_sender(const go_addr_key_t *chan_key,
                                                         const chan_handoff_t *handoff) {
    direct_chan_handoff_t *existing = bpf_map_lookup_elem(&direct_channel_senders, chan_key);
    direct_chan_handoff_t value = {};

    // More than one waiter on the same channel cannot be paired safely by channel pointer alone.
    if (existing || !handoff) {
        value.ambiguous = true;
    } else {
        value.handoff = *handoff;
    }

    bpf_map_update_elem(&direct_channel_senders, chan_key, &value, BPF_ANY);
}

static __always_inline void record_direct_channel_receiver(const go_addr_key_t *chan_key,
                                                           const chan_handoff_t *handoff) {
    direct_chan_handoff_t *existing = bpf_map_lookup_elem(&direct_channel_receivers, chan_key);
    direct_chan_handoff_t value = {};

    if (existing || !handoff) {
        value.ambiguous = true;
    } else {
        value.handoff = *handoff;
    }

    bpf_map_update_elem(&direct_channel_receivers, chan_key, &value, BPF_ANY);
}

static __always_inline void emit_direct_channel_handoff(const go_addr_key_t *chan_key) {
    direct_chan_handoff_t *sender = bpf_map_lookup_elem(&direct_channel_senders, chan_key);
    direct_chan_handoff_t *receiver = bpf_map_lookup_elem(&direct_channel_receivers, chan_key);
    if (sender && receiver && !sender->ambiguous && !receiver->ambiguous) {
        emit_channel_handoff(&sender->handoff, &receiver->handoff);
    }

    bpf_map_delete_elem(&direct_channel_senders, chan_key);
    bpf_map_delete_elem(&direct_channel_receivers, chan_key);
}

static __always_inline void record_buffered_channel_sender(const go_addr_key_t *chan_key,
                                                           u64 sendx,
                                                           u64 dataqsiz,
                                                           const chan_handoff_t *sender) {
    if (!chan_key || !sender || dataqsiz == 0) {
        return;
    }

    chan_handoff_key_t key = {
        .chan = *chan_key,
        .slot = previous_channel_slot(sendx, dataqsiz),
    };
    bpf_map_update_elem(&buffered_channel_senders, &key, sender, BPF_ANY);
}

static __always_inline bool
consume_buffered_channel_sender(const go_addr_key_t *chan_key, u64 slot, chan_handoff_t *receiver) {
    if (!chan_key) {
        return false;
    }

    chan_handoff_key_t key = {
        .chan = *chan_key,
        .slot = slot,
    };
    chan_handoff_t *sender = bpf_map_lookup_elem(&buffered_channel_senders, &key);
    if (!sender) {
        return false;
    }

    if (receiver) {
        emit_channel_handoff(sender, receiver);
    }
    bpf_map_delete_elem(&buffered_channel_senders, &key);
    return true;
}

static __always_inline int channel_send_start(struct pt_regs *ctx) {
    const u64 chan_ptr = (u64)GO_PARAM1(ctx);
    if (!chan_ptr) {
        return 0;
    }

    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    chan_func_invocation_t invocation = {.chan_ptr = chan_ptr};
    if (current_obi_handoff(ctx, &invocation.handoff)) {
        invocation.has_handoff = true;
    }

    if (bpf_map_update_elem(&chansend_invocations, &g_key, &invocation, BPF_ANY)) {
        return 0;
    }

    u64 dataqsiz = 0;
    if (!read_channel_dataqsiz((void *)chan_ptr, &dataqsiz) || dataqsiz != 0) {
        return 0;
    }

    go_addr_key_t chan_key = {};
    go_addr_key_from_id(&chan_key, (void *)chan_ptr);

    if (invocation.has_handoff) {
        record_direct_channel_sender(&chan_key, &invocation.handoff);
    } else {
        record_direct_channel_sender(&chan_key, NULL);
    }

    return 0;
}

static __always_inline int channel_send_return(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    chan_func_invocation_t *invocation = bpf_map_lookup_elem(&chansend_invocations, &g_key);
    if (!invocation) {
        return 0;
    }

    u64 dataqsiz = 0;
    go_addr_key_t chan_key = {};
    go_addr_key_from_id(&chan_key, (void *)invocation->chan_ptr);

    if (!read_channel_dataqsiz((void *)invocation->chan_ptr, &dataqsiz)) {
        goto done;
    }

    if (dataqsiz == 0) {
        emit_direct_channel_handoff(&chan_key);
        goto done;
    }

    u64 qcount = 0;
    u64 sendx = 0;
    if (!read_channel_qcount((void *)invocation->chan_ptr, &qcount)) {
        goto done;
    }

    if (qcount == 0) {
        if (invocation->has_handoff) {
            record_direct_channel_sender(&chan_key, &invocation->handoff);
        } else {
            record_direct_channel_sender(&chan_key, NULL);
        }
        emit_direct_channel_handoff(&chan_key);
        goto done;
    }

    if (invocation->has_handoff && read_channel_sendx((void *)invocation->chan_ptr, &sendx)) {
        record_buffered_channel_sender(&chan_key, sendx, dataqsiz, &invocation->handoff);
    }

done:
    bpf_map_delete_elem(&direct_channel_senders, &chan_key);
    bpf_map_delete_elem(&chansend_invocations, &g_key);
    return 0;
}

static __always_inline int channel_recv_start(struct pt_regs *ctx) {
    const u64 chan_ptr = (u64)GO_PARAM1(ctx);
    if (!chan_ptr) {
        return 0;
    }

    u64 dataqsiz = 0;
    if (!read_channel_dataqsiz((void *)chan_ptr, &dataqsiz)) {
        return 0;
    }

    chan_func_invocation_t invocation = {.chan_ptr = chan_ptr};
    if (current_obi_handoff(ctx, &invocation.handoff)) {
        invocation.has_handoff = true;
    }

    if (dataqsiz != 0) {
        if (!read_channel_recvx((void *)chan_ptr, &invocation.recvx)) {
            return 0;
        }

        u64 qcount = 0;
        invocation.direct_handoff = read_channel_qcount((void *)chan_ptr, &qcount) && qcount == 0;
    } else {
        invocation.direct_handoff = true;
    }

    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    if (bpf_map_update_elem(&chanrecv_invocations, &g_key, &invocation, BPF_ANY)) {
        return 0;
    }

    if (invocation.direct_handoff) {
        go_addr_key_t chan_key = {};
        go_addr_key_from_id(&chan_key, (void *)chan_ptr);

        if (invocation.has_handoff) {
            record_direct_channel_receiver(&chan_key, &invocation.handoff);
        } else {
            record_direct_channel_receiver(&chan_key, NULL);
        }
    }

    return 0;
}

static __always_inline int channel_recv_return(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    chan_func_invocation_t *invocation = bpf_map_lookup_elem(&chanrecv_invocations, &g_key);
    if (!invocation) {
        return 0;
    }

    u64 dataqsiz = 0;
    go_addr_key_t chan_key = {};
    go_addr_key_from_id(&chan_key, (void *)invocation->chan_ptr);

    if (!read_channel_dataqsiz((void *)invocation->chan_ptr, &dataqsiz)) {
        goto done;
    }

    if (dataqsiz == 0) {
        emit_direct_channel_handoff(&chan_key);
        goto done;
    }

    u64 recvx = 0;
    bool consumed_buffered_sender = false;
    const bool recvx_read = read_channel_recvx((void *)invocation->chan_ptr, &recvx);
    const bool recvx_changed = recvx_read && recvx != invocation->recvx;
    const bool single_slot_buffered_receive = dataqsiz == 1 && !invocation->direct_handoff;
    if (recvx_changed || single_slot_buffered_receive) {
        const u64 slot = previous_channel_slot(recvx, dataqsiz);
        if (invocation->has_handoff) {
            consumed_buffered_sender =
                consume_buffered_channel_sender(&chan_key, slot, &invocation->handoff);
        } else {
            consumed_buffered_sender = consume_buffered_channel_sender(&chan_key, slot, NULL);
        }
    }

    if (recvx_read && !consumed_buffered_sender && !recvx_changed && dataqsiz != 1) {
        u64 qcount = 0;
        if (read_channel_qcount((void *)invocation->chan_ptr, &qcount) && qcount == 0) {
            if (!invocation->direct_handoff) {
                if (invocation->has_handoff) {
                    record_direct_channel_receiver(&chan_key, &invocation->handoff);
                } else {
                    record_direct_channel_receiver(&chan_key, NULL);
                }
            }
            emit_direct_channel_handoff(&chan_key);
        }
    }

done:
    bpf_map_delete_elem(&direct_channel_receivers, &chan_key);
    bpf_map_delete_elem(&chanrecv_invocations, &g_key);
    return 0;
}

SEC("uprobe/runtime_chansend1")
int obi_uprobe_runtime_chansend1(struct pt_regs *ctx) {
    return channel_send_start(ctx);
}

SEC("uprobe/runtime_chansend1_return")
int obi_uprobe_runtime_chansend1_return(struct pt_regs *ctx) {
    return channel_send_return(ctx);
}

SEC("uprobe/runtime_chanrecv1")
int obi_uprobe_runtime_chanrecv1(struct pt_regs *ctx) {
    return channel_recv_start(ctx);
}

SEC("uprobe/runtime_chanrecv1_return")
int obi_uprobe_runtime_chanrecv1_return(struct pt_regs *ctx) {
    return channel_recv_return(ctx);
}

SEC("uprobe/runtime_chanrecv2")
int obi_uprobe_runtime_chanrecv2(struct pt_regs *ctx) {
    return channel_recv_start(ctx);
}

SEC("uprobe/runtime_chanrecv2_return")
int obi_uprobe_runtime_chanrecv2_return(struct pt_regs *ctx) {
    return channel_recv_return(ctx);
}

enum gstatus {
    // _Gidle: just allocated, not yet initialized
    g_idle = 0,
    // _Grunnable: on a run queue, not executing user code
    g_runnable, // 1
    // _Grunning: may execute user code, stack is owned, assigned to M and P
    g_running, // 2
    // _Gsyscall: executing a system call, not user code, stack owned
    g_syscall, // 3
    // _Gwaiting: blocked in runtime, not executing user code, not on run queue
    g_waiting, // 4
    // _Gmoribund_unused: currently unused, hardcoded in gdb scripts
    g_moribund_unused, // 5
    // _Gdead: currently unused, may have just exited or on free list
    g_dead, // 6
    // _Genqueue_unused: currently unused
    g_enqueue_unused, // 7
    // _Gcopystack: stack is being moved, not executing user code
    g_copystack, // 8
    // _Gpreempted: stopped for suspendG preemption
    g_preempted, // 9
};

// NOTE: this is a hot path in the Go runtime, fetching offsets from the offsets map
// introduces a non negligible overhead. These structs appear to be stable since
// old versions of Go, so keep the values hardcoded.
//
// pahole -C runtime.g main
//
// struct runtime.g {
//  runtime.stack              stack;                /*     0    16 */
//  uintptr                    stackguard0;          /*    16     8 */
//  uintptr                    stackguard1;          /*    24     8 */
//  runtime._panic *           _panic;               /*    32     8 */
//  runtime._defer *           _defer;               /*    40     8 */
//  runtime.m *                m;                    /*    48     8 */
//  ...
// }
//
// pahole -C runtime.m main
//
// struct runtime.m {
//  runtime.g *                g0;                   /*     0     8 */
//  runtime.gobuf              morebuf;              /*     8    48 */
//  uint32                     divmod;               /*    56     4 */
//
//  /* XXX 4 bytes hole, try to pack */
//
//  /* --- cacheline 1 boundary (64 bytes) --- */
//  uint64                     procid;               /*    64     8 */
//  ...
// }
enum offsets : u8 {
    k_g_m_off = 0x30,
    k_m_procid_off = 0x40,
};

SEC("uprobe/runtime.mstart1")
int obi_uprobe_runtime_mstart1(struct pt_regs *ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    void *g = (void *)GOROUTINE_PTR(ctx);
    void *m = NULL;

    bpf_probe_read_user(&m, sizeof(m), (void *)((char *)g + k_g_m_off));
    if (!m) {
        return 0;
    }

    bpf_map_update_elem(&mptr_to_root_tid, &m, &(u32){pid_tgid}, BPF_ANY);
    return 0;
}

SEC("uprobe/runtime.mexit")
int obi_uprobe_runtime_mexit(struct pt_regs *ctx) {
    void *g = (void *)GOROUTINE_PTR(ctx);
    void *m = NULL;

    bpf_probe_read_user(&m, sizeof(m), (void *)((char *)g + k_g_m_off));
    if (!m) {
        return 0;
    }

    bpf_map_delete_elem(&mptr_to_root_tid, &m);
    return 0;
}

// gp *g, oldval, newval uint32
SEC("uprobe/runtime.casgstatus")
int obi_uprobe_runtime_casgstatus(struct pt_regs *ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    void *g = (void *)GO_PARAM1(ctx);
    void *m = NULL;

    bpf_probe_read_user(&m, sizeof(m), (void *)((char *)g + k_g_m_off));
    if (!m) {
        return 0;
    }

    u64 procid = 0;
    bpf_probe_read_user(&procid, sizeof(procid), (void *)((char *)m + k_m_procid_off));
    if (procid == 0) {
        return 0;
    }

    const u32 pid = pid_tgid >> 32;
    u32 *root_tid = bpf_map_lookup_elem(&mptr_to_root_tid, &m);
    if (root_tid != NULL) {
        procid = *root_tid;
    }

    const u64 g_pid_tgid = ((u64)pid << 32) | (procid & 0xffffffff);
    go_addr_key_t g_key = {
        .addr = (u64)g,
        .pid = pid,
    };

    // grpc
    grpc_srv_func_invocation_t *grpc_server_inv;
    grpc_client_func_invocation_t *grpc_client_inv;
    // http
    server_http_func_invocation_t *http_server_inv;
    // kafka_go
    tp_info_t *kafka_go_tp;
    // mongo
    mongo_go_client_req_t *mongo;
    // redis
    redis_client_req_t *redis;
    // sql
    sql_func_invocation_t *sql;

    obi_ctx_info_t obi_info = {};

    const u32 newval = (u32)(uintptr_t)GO_PARAM3(ctx);
    switch (newval) {
    case g_running:
    case g_syscall:
        // grpc
        grpc_server_inv = bpf_map_lookup_elem(&ongoing_grpc_server_requests, &g_key);
        if (grpc_server_inv) {
            obi_ctx__set_(g_pid_tgid, &grpc_server_inv->tp, &obi_info);
            return 0;
        }
        grpc_client_inv = bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);
        if (grpc_client_inv) {
            obi_ctx__set_(g_pid_tgid, &grpc_client_inv->tp, &obi_info);
            return 0;
        }
        // http
        http_server_inv = bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);
        if (http_server_inv) {
            obi_ctx__set_(g_pid_tgid, &http_server_inv->tp, &obi_info);
            return 0;
        }
        // kafka_go
        kafka_go_tp = bpf_map_lookup_elem(&produce_traceparents_by_goroutine, &g_key);
        if (kafka_go_tp) {
            obi_ctx__set_(g_pid_tgid, kafka_go_tp, &obi_info);
            return 0;
        }
        // mongo
        mongo = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
        if (mongo) {
            obi_ctx__set_(g_pid_tgid, &mongo->tp, &obi_info);
            return 0;
        }
        // redis
        redis = bpf_map_lookup_elem(&ongoing_redis_requests, &g_key);
        if (redis) {
            obi_ctx__set_(g_pid_tgid, &redis->tp, &obi_info);
            return 0;
        }
        // sql
        sql = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
        if (sql) {
            obi_ctx__set_(g_pid_tgid, &sql->tp, &obi_info);
            return 0;
        }

        break;
    default:
        obi_ctx__del(g_pid_tgid);
    }

    return 0;
}
