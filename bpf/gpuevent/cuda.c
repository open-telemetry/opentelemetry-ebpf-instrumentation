// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
// Source: https://github.com/facebookincubator/strobelight/blob/5d84bcfdd9abccc615b45a390bfd7bba7097dc51/strobelight/src/profilers/gpuevent_snoop/bpf/gpuevent_snoop.bpf.c
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <gpuevent/cuda.h>
#include <gpuevent/gpu_ringbuf.h>

#include <logger/bpf_dbg.h>

#include <pid/pid.h>
#include <common/preempt_guard.h>
#include <common/pin_internal.h>

const cuda_kernel_launch_t *unused_gpu __attribute__((unused));
const cuda_memcpy_t *unused_gpu1 __attribute__((unused));
const cuda_size_event_t *unused_gpu2 __attribute__((unused));
const cuda_call_event_t *unused_gpu3 __attribute__((unused));

enum {
    k_event_kernel_launch = 1,
    k_event_malloc = 2,
    k_event_memcpy = 3,
    k_event_graph_launch = 4,
    k_event_free = 5,
    k_event_memset = 6,
    k_event_stream_create = 7,
    k_event_stream_destroy = 8,
    k_event_event_record = 9,
    k_event_event_synchronize = 10,
    k_event_stream_synchronize = 11,
    k_event_device_synchronize = 12,
    k_event_host_register = 13,
};

// Tracks cudaMalloc arguments from entry to return so the allocated pointer can
// be correlated with its size for byte-accurate cudaFree metrics. LRU eviction
// bounds the map if a target exits or is deselected while a call is in flight.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, OBI_PIN_INTERNAL);
    __type(key, u64);
    __type(value, cuda_malloc_ctx_t);
} cuda_malloc_ctx SEC(".maps");

// Tracks cudaFree arguments from entry to return so the free is only reported
// once the return code confirms the memory was released.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, OBI_PIN_INTERNAL);
    __type(key, u64);
    __type(value, cuda_free_ctx_t);
} cuda_free_ctx SEC(".maps");

// Maps a tracked allocation, identified by process and device pointer, to its
// size. Populated by the cudaMalloc uretprobe and consumed by the cudaFree
// probes. LRU eviction bounds the map when targets leak or outlive entries.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __uint(pinning, OBI_PIN_INTERNAL);
    __type(key, cuda_alloc_key_t);
    __type(value, s64);
} cuda_alloc_sizes SEC(".maps");

// Per-thread in-flight marker for runtime API calls that libcudart implements
// by calling into libcuda. Set at the runtime uprobe entry and consumed by the
// driver API probes, so a launch observed through both libraries (the runtime
// API is a thin wrapper over the driver API) is reported once. The matching
// runtime uretprobes clear markers for calls that never reach the driver.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, OBI_PIN_INTERNAL);
    __type(key, u64);
    __type(value, u8);
} cuda_runtime_launch_ctx SEC(".maps");

static __always_inline void submit_size_event(const u8 flags, const s64 size) {
    cuda_size_event_t *e = bpf_ringbuf_reserve(&gpu_events, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return;
    }

    e->flags = flags;
    task_pid(&e->pid_info);
    e->size = size;

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void submit_call_event(const u8 flags) {
    cuda_call_event_t *e = bpf_ringbuf_reserve(&gpu_events, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return;
    }

    e->flags = flags;
    task_pid(&e->pid_info);

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void submit_kernel_launch(const u64 func_off,
                                                 const u32 grid_x,
                                                 const u32 grid_y,
                                                 const u32 grid_z,
                                                 const u32 block_x,
                                                 const u32 block_y,
                                                 const u32 block_z) {
    cuda_kernel_launch_t *e = bpf_ringbuf_reserve(&gpu_events, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return;
    }

    e->flags = k_event_kernel_launch;
    task_pid(&e->pid_info);

    e->kern_func_off = func_off;
    e->grid_x = grid_x;
    e->grid_y = grid_y;
    e->grid_z = grid_z;
    e->block_x = block_x;
    e->block_y = block_y;
    e->block_z = block_z;

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void mark_runtime_launch(const u64 id) {
    const u8 in_flight = 1;
    bpf_map_update_elem(&cuda_runtime_launch_ctx, &id, &in_flight, BPF_ANY);
}

// Returns true (and consumes the marker) when a driver API call duplicates a
// runtime API call still in flight on the same thread, meaning the launch was
// already reported by the runtime uprobe.
static __always_inline bool suppress_driver_dup(const u64 id) {
    if (bpf_map_lookup_elem(&cuda_runtime_launch_ctx, &id) == NULL) {
        return false;
    }
    bpf_map_delete_elem(&cuda_runtime_launch_ctx, &id);
    return true;
}

SEC("uprobe/cudaLaunchKernel")
int BPF_KPROBE_GUARDED(
    obi_cuda_launch, u64 func_off, u64 grid_xy, u64 grid_z, u64 block_xy, u64 block_z) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaLaunchKernel id=%llx ===", id);

    mark_runtime_launch(id);

    submit_kernel_launch(func_off,
                         (u32)grid_xy,
                         (u32)(grid_xy >> 32),
                         (u32)grid_z,
                         (u32)block_xy,
                         (u32)(block_xy >> 32),
                         (u32)block_z);

    return 0;
}

// Clears the in-flight marker once the runtime call returns. Calls that reached
// the driver already consumed it; this only cleans up markers left behind by
// calls that failed before entering libcuda, which would otherwise wrongly
// suppress the thread's next direct driver API launch.
SEC("uretprobe/cudaLaunchKernel")
int BPF_KRETPROBE_GUARDED(obi_cuda_launch_ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&cuda_runtime_launch_ctx, &id);

    return 0;
}

// cuLaunchKernel(const void *func, u32 grid_x, u32 grid_y, u32 grid_z, u32 block_x, u32 block_y,
//                u32 block_z, u32 shared_mem_bytes, CUstream stream, void **params, void **extra)
// The seventh argument does not fit in registers: it spills to the stack on
// x86-64 and is passed in x6 on arm64.
SEC("uprobe/cuLaunchKernel")
int BPF_KPROBE_GUARDED(
    obi_cu_launch, void *func, u32 grid_x, u32 grid_y, u32 grid_z, u32 block_x, u32 block_y) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    if (suppress_driver_dup(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cuLaunchKernel id=%llx ===", id);

    u64 block_z = 0;
#if defined(__TARGET_ARCH_x86)
    bpf_probe_read_user(&block_z, sizeof(u32), (const void *)(PT_REGS_SP(ctx) + 8));
#elif defined(__TARGET_ARCH_arm64)
    block_z = ((PT_REGS_ARM64 *)ctx)->regs[6];
#endif

    submit_kernel_launch((u64)func, grid_x, grid_y, grid_z, block_x, block_y, (u32)block_z);

    return 0;
}

// cuLaunchKernelEx(const CUlaunchConfig *config, void *func, void **params, void **extra)
SEC("uprobe/cuLaunchKernelEx")
int BPF_KPROBE_GUARDED(obi_cu_launch_ex, void *config, void *func, void **params, void **extra) {
    (void)ctx;
    (void)params;
    (void)extra;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    if (suppress_driver_dup(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cuLaunchKernelEx id=%llx ===", id);

    cu_launch_config_t cfg = {};
    bpf_probe_read_user(&cfg, sizeof(cfg), config);

    submit_kernel_launch(
        (u64)func, cfg.grid_x, cfg.grid_y, cfg.grid_z, cfg.block_x, cfg.block_y, cfg.block_z);

    return 0;
}

SEC("uprobe/cudaMalloc")
int BPF_KPROBE_GUARDED(obi_cuda_malloc, void **devPtr, size_t size) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaMalloc id=%llx ===", id);

    submit_size_event(k_event_malloc, (s64)size);

    cuda_malloc_ctx_t malloc_ctx = {};
    malloc_ctx.dev_ptr_addr = (u64)devPtr;
    malloc_ctx.size = (s64)size;
    bpf_map_update_elem(&cuda_malloc_ctx, &id, &malloc_ctx, BPF_ANY);

    return 0;
}

SEC("uretprobe/cudaMalloc")
int BPF_KRETPROBE_GUARDED(obi_cuda_malloc_ret, int ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    // Consume the entry context unconditionally, before any filtering, so a
    // target deselected (or exiting) while the call was in flight cannot leak
    // the entry.
    cuda_malloc_ctx_t malloc_ctx = {};
    bool tracked = false;
    const cuda_malloc_ctx_t *stored = bpf_map_lookup_elem(&cuda_malloc_ctx, &id);
    if (stored) {
        malloc_ctx.dev_ptr_addr = stored->dev_ptr_addr;
        malloc_ctx.size = stored->size;
        tracked = true;
    }
    bpf_map_delete_elem(&cuda_malloc_ctx, &id);

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cudaMalloc id=%llx ret=%d ===", id, ret);

    if (ret != 0 || !tracked) {
        return 0;
    }

    void *dev_ptr = NULL;
    if (bpf_probe_read_user(&dev_ptr, sizeof(dev_ptr), (void *)malloc_ctx.dev_ptr_addr) != 0) {
        return 0;
    }

    const u64 ptr_val = (u64)dev_ptr;
    if (ptr_val != 0) {
        cuda_alloc_key_t alloc_key = {
            .tgid = id >> 32,
            .ptr = ptr_val,
        };
        if (bpf_map_update_elem(&cuda_alloc_sizes, &alloc_key, &malloc_ctx.size, BPF_ANY) != 0) {
            bpf_dbg_printk("Failed to track cudaMalloc allocation");
        }
    }

    return 0;
}

SEC("uprobe/cudaFree")
int BPF_KPROBE_GUARDED(obi_cuda_free, void *devPtr) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaFree id=%llx ===", id);

    cuda_alloc_key_t alloc_key = {
        .tgid = id >> 32,
        .ptr = (u64)devPtr,
    };
    const s64 *size = bpf_map_lookup_elem(&cuda_alloc_sizes, &alloc_key);
    if (!size) {
        // Pointer was not allocated through cudaMalloc (or tracking was lost);
        // do not emit a byte metric for it.
        return 0;
    }

    // Report the free only once the return confirms the memory was released.
    cuda_free_ctx_t free_ctx = {
        .dev_ptr = (u64)devPtr,
        .size = *size,
    };
    bpf_map_update_elem(&cuda_free_ctx, &id, &free_ctx, BPF_ANY);

    return 0;
}

SEC("uretprobe/cudaFree")
int BPF_KRETPROBE_GUARDED(obi_cuda_free_ret, int ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    // Consume the entry context unconditionally, before any filtering, so a
    // target deselected (or exiting) while the call was in flight cannot leak
    // the entry.
    cuda_free_ctx_t free_ctx = {};
    bool tracked = false;
    const cuda_free_ctx_t *stored = bpf_map_lookup_elem(&cuda_free_ctx, &id);
    if (stored) {
        free_ctx.dev_ptr = stored->dev_ptr;
        free_ctx.size = stored->size;
        tracked = true;
    }
    bpf_map_delete_elem(&cuda_free_ctx, &id);

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cudaFree id=%llx ret=%d ===", id, ret);

    if (ret != 0 || !tracked) {
        // The free failed and the allocation is still live, or the pointer was
        // not tracked; keep the size entry so a later successful free can
        // report it.
        return 0;
    }

    submit_size_event(k_event_free, free_ctx.size);

    cuda_alloc_key_t alloc_key = {
        .tgid = id >> 32,
        .ptr = free_ctx.dev_ptr,
    };
    bpf_map_delete_elem(&cuda_alloc_sizes, &alloc_key);

    return 0;
}

SEC("uprobe/cudaMemcpyAsync")
int BPF_KPROBE_GUARDED(obi_cuda_memcpy, void *dst, void *src, size_t size, u8 kind) {
    (void)ctx;
    (void)dst;
    (void)src;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaMemcpyAsync id=%llx, kind=%d ===", id, kind);

    cuda_memcpy_t *e = bpf_ringbuf_reserve(&gpu_events, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return 0;
    }

    e->flags = k_event_memcpy;
    task_pid(&e->pid_info);
    e->size = (s64)size;
    e->kind = kind;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/cudaGraphLaunch")
int BPF_KPROBE_GUARDED(obi_graph_launch) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaGraphLaunch id=%llx ===", id);

    mark_runtime_launch(id);

    submit_call_event(k_event_graph_launch);

    return 0;
}

// Clears the in-flight marker once the runtime call returns; see
// obi_cuda_launch_ret for why this must not be skipped.
SEC("uretprobe/cudaGraphLaunch")
int BPF_KRETPROBE_GUARDED(obi_graph_launch_ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&cuda_runtime_launch_ctx, &id);

    return 0;
}

SEC("uprobe/cuGraphLaunch")
int BPF_KPROBE_GUARDED(obi_cu_graph_launch) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    if (suppress_driver_dup(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cuGraphLaunch id=%llx ===", id);
    submit_call_event(k_event_graph_launch);

    return 0;
}

SEC("uprobe/cudaMemset")
int BPF_KPROBE_GUARDED(obi_cuda_memset, void *devPtr, int value, size_t count) {
    (void)ctx;
    (void)devPtr;
    (void)value;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaMemset id=%llx ===", id);
    submit_size_event(k_event_memset, (s64)count);

    return 0;
}

SEC("uprobe/cudaStreamCreate")
int BPF_KPROBE_GUARDED(obi_cuda_stream_create, void *stream) {
    (void)ctx;
    (void)stream;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaStreamCreate id=%llx ===", id);
    submit_call_event(k_event_stream_create);

    return 0;
}

SEC("uprobe/cudaStreamCreateWithFlags")
int BPF_KPROBE_GUARDED(obi_cuda_stream_create_with_flags, void *stream, unsigned int flags) {
    (void)ctx;
    (void)stream;
    (void)flags;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaStreamCreateWithFlags id=%llx ===", id);
    submit_call_event(k_event_stream_create);

    return 0;
}

SEC("uprobe/cudaStreamCreateWithPriority")
int BPF_KPROBE_GUARDED(obi_cuda_stream_create_with_priority,
                       void *stream,
                       unsigned int flags,
                       int priority) {
    (void)ctx;
    (void)stream;
    (void)flags;
    (void)priority;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaStreamCreateWithPriority id=%llx ===", id);
    submit_call_event(k_event_stream_create);

    return 0;
}

SEC("uprobe/cudaStreamDestroy")
int BPF_KPROBE_GUARDED(obi_cuda_stream_destroy, void *stream) {
    (void)ctx;
    (void)stream;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaStreamDestroy id=%llx ===", id);
    submit_call_event(k_event_stream_destroy);

    return 0;
}

SEC("uprobe/cudaEventRecord")
int BPF_KPROBE_GUARDED(obi_cuda_event_record, void *event, void *stream) {
    (void)ctx;
    (void)event;
    (void)stream;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaEventRecord id=%llx ===", id);
    submit_call_event(k_event_event_record);

    return 0;
}

SEC("uprobe/cudaEventRecordWithFlags")
int BPF_KPROBE_GUARDED(obi_cuda_event_record_with_flags,
                       void *event,
                       void *stream,
                       unsigned int flags) {
    (void)ctx;
    (void)event;
    (void)stream;
    (void)flags;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaEventRecordWithFlags id=%llx ===", id);
    submit_call_event(k_event_event_record);

    return 0;
}

SEC("uprobe/cudaEventSynchronize")
int BPF_KPROBE_GUARDED(obi_cuda_event_synchronize, void *event) {
    (void)ctx;
    (void)event;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaEventSynchronize id=%llx ===", id);
    submit_call_event(k_event_event_synchronize);

    return 0;
}

SEC("uprobe/cudaStreamSynchronize")
int BPF_KPROBE_GUARDED(obi_cuda_stream_synchronize, void *stream) {
    (void)ctx;
    (void)stream;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaStreamSynchronize id=%llx ===", id);
    submit_call_event(k_event_stream_synchronize);

    return 0;
}

SEC("uprobe/cudaDeviceSynchronize")
int BPF_KPROBE_GUARDED(obi_cuda_device_synchronize) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaDeviceSynchronize id=%llx ===", id);
    submit_call_event(k_event_device_synchronize);

    return 0;
}

SEC("uprobe/cudaHostRegister")
int BPF_KPROBE_GUARDED(obi_cuda_host_register, void *ptr, size_t size, unsigned int flags) {
    (void)ctx;
    (void)ptr;
    (void)flags;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaHostRegister id=%llx ===", id);
    submit_size_event(k_event_host_register, (s64)size);

    return 0;
}
