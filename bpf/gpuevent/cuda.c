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
const cuda_device_event_t *unused_gpu4 __attribute__((unused));

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
    k_event_device_info = 14,
};

// Which parts of a device identity an introspection return scan managed to read.
enum {
    k_device_has_uuid = 1,
    k_device_has_name = 2,
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

// Device the calling thread is bound to, learned from cudaSetDevice and
// cudaGetDevice. Keyed by thread because CUDA's current device is per host
// thread. A thread that never selected one is absent here, which means CUDA's
// default device.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __uint(pinning, OBI_PIN_INTERNAL);
    __type(key, u64);
    __type(value, u32);
} cuda_thread_device SEC(".maps");

// Identity of a device index as revealed by the introspection APIs. Keyed by
// process because device indices are only unique within one.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __uint(pinning, OBI_PIN_INTERNAL);
    __type(key, cuda_device_key_t);
    __type(value, cuda_device_info_t);
} cuda_device_info SEC(".maps");

// Per-thread context captured at the entry of a device introspection call and
// consumed at its return, once the callee has written into the receiving buffer.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, OBI_PIN_INTERNAL);
    __type(key, u64);
    __type(value, cuda_introspect_ctx_t);
} cuda_introspect_ctx SEC(".maps");

// Tracks cudaSetDevice arguments from entry to return so a failed call does not
// bind the thread to a device it never selected.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, OBI_PIN_INTERNAL);
    __type(key, u64);
    __type(value, cuda_set_device_ctx_t);
} cuda_set_device_ctx SEC(".maps");

// Fills in the device an observed CUDA call ran on: the process-local index the
// calling thread is bound to, and the UUID that index maps to. An all-zero UUID
// means the index identity has not been observed for the process yet, which
// userspace reports as an unknown device.
static __always_inline void resolve_device(const u64 id, cuda_device_t *dev) {
    dev->index = 0;
    __builtin_memset(dev->uuid, 0, sizeof(dev->uuid));

    const u32 *thread_dev = bpf_map_lookup_elem(&cuda_thread_device, &id);
    if (thread_dev) {
        dev->index = *thread_dev;
    }

    cuda_device_key_t key = {
        .tgid = id >> 32,
        .index = dev->index,
    };
    const cuda_device_info_t *info = bpf_map_lookup_elem(&cuda_device_info, &key);
    if (info) {
        __builtin_memcpy(dev->uuid, info->uuid, sizeof(dev->uuid));
    }
}

static __always_inline void submit_size_event(const u8 flags, const s64 size) {
    cuda_size_event_t *e = bpf_ringbuf_reserve(&gpu_events, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return;
    }

    e->flags = flags;
    task_pid(&e->pid_info);
    e->size = size;
    resolve_device(bpf_get_current_pid_tgid(), &e->device);

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
    resolve_device(bpf_get_current_pid_tgid(), &e->device);

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
    resolve_device(bpf_get_current_pid_tgid(), &e->device);

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

// Reports a device identity to userspace, which caches it by UUID so the
// per-call metrics, whose events only carry the UUID, can be named. Only the
// rare introspection calls travel this way.
static __always_inline void submit_device_event(const u32 index, const cuda_device_info_t *info) {
    cuda_device_event_t *e = bpf_ringbuf_reserve(&gpu_events, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return;
    }

    e->flags = k_event_device_info;
    task_pid(&e->pid_info);
    e->index = index;
    __builtin_memcpy(e->uuid, info->uuid, sizeof(e->uuid));
    __builtin_memcpy(e->name, info->name, sizeof(e->name));

    bpf_ringbuf_submit(e, 0);
}

// Merges the parts of a device identity an introspection call revealed into the
// device table and reports the result. The parts the call did not provide are
// kept from earlier calls, so a UUID-only or name-only call cannot clear the
// other. uuid and name are only dereferenced when their flag is provided.
static __always_inline void merge_device_info(
    const u64 id, const u32 index, const u8 provided, const u8 *uuid, const char *name) {
    if (provided == 0) {
        return;
    }

    cuda_device_key_t key = {
        .tgid = id >> 32,
        .index = index,
    };

    cuda_device_info_t info = {};
    const cuda_device_info_t *stored = bpf_map_lookup_elem(&cuda_device_info, &key);
    if (stored) {
        __builtin_memcpy(info.uuid, stored->uuid, sizeof(info.uuid));
        __builtin_memcpy(info.name, stored->name, sizeof(info.name));
    }

    if (provided & k_device_has_uuid) {
        __builtin_memcpy(info.uuid, uuid, sizeof(info.uuid));
    }
    if (provided & k_device_has_name) {
        __builtin_memcpy(info.name, name, sizeof(info.name));
    }

    if (bpf_map_update_elem(&cuda_device_info, &key, &info, BPF_ANY) != 0) {
        bpf_dbg_printk("Failed to record cuda device info");
        return;
    }

    submit_device_event(index, &info);
}

// Reads the model name and UUID out of the cudaDeviceProp the callee filled in.
static __always_inline void merge_props(const u64 id, const cuda_introspect_ctx_t *intro) {
    u8 provided = 0;

    u8 uuid[k_cuda_uuid_len] = {};
    if (bpf_probe_read_user(
            uuid, sizeof(uuid), (const void *)(intro->buf_addr + k_cuda_prop_uuid_off)) == 0) {
        provided |= k_device_has_uuid;
    }

    char name[k_cuda_name_len] = {};
    if (bpf_probe_read_user(
            name, sizeof(name), (const void *)(intro->buf_addr + k_cuda_prop_name_off)) == 0) {
        provided |= k_device_has_name;
    }

    merge_device_info(id, intro->index, provided, uuid, name);
}

// Remembers where the result of a device introspection call will land, so its
// return probe knows what to read and which device it belongs to.
static __always_inline void capture_introspect(
    const u64 id, const u64 buf_addr, const u32 index, const u32 len, const u32 kind) {
    cuda_introspect_ctx_t intro = {
        .buf_addr = buf_addr,
        .index = index,
        .len = len,
        .kind = kind,
    };
    bpf_map_update_elem(&cuda_introspect_ctx, &id, &intro, BPF_ANY);
}

// Consumes the entry context unconditionally, before any filtering, so a target
// deselected (or exiting) while the call was in flight cannot leak the entry.
// Returns false when the entry captured nothing, or when the stored context
// belongs to a different introspection call: the runtime device property query
// is implemented in terms of the driver API, whose inner calls overwrite this
// context but report the same identity on their own return.
static __always_inline bool
consume_introspect(const u64 id, const u32 kind, cuda_introspect_ctx_t *intro) {
    const cuda_introspect_ctx_t *stored = bpf_map_lookup_elem(&cuda_introspect_ctx, &id);
    const bool captured = stored != NULL && stored->kind == kind;
    if (captured) {
        intro->buf_addr = stored->buf_addr;
        intro->index = stored->index;
        intro->len = stored->len;
        intro->kind = stored->kind;
    }
    bpf_map_delete_elem(&cuda_introspect_ctx, &id);

    return captured;
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
    resolve_device(id, &e->device);

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

// Device identity. The per-call APIs carry no reference to the device they run on,
// so the identity a metric is labeled with is recovered from the introspection
// calls a target makes: cudaSetDevice and cudaGetDevice bind the calling thread to
// a process-local index, while the properties and UUID/name queries reveal which
// physical device that index is.

SEC("uprobe/cudaSetDevice")
int BPF_KPROBE_GUARDED(obi_cuda_set_device, int device) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaSetDevice id=%llx device=%d ===", id, device);

    const cuda_set_device_ctx_t set_ctx = {
        .index = (u32)device,
    };
    bpf_map_update_elem(&cuda_set_device_ctx, &id, &set_ctx, BPF_ANY);

    return 0;
}

SEC("uretprobe/cudaSetDevice")
int BPF_KRETPROBE_GUARDED(obi_cuda_set_device_ret, int ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    // Consume the entry context unconditionally, before any filtering, so a
    // target deselected (or exiting) while the call was in flight cannot leak
    // the entry.
    cuda_set_device_ctx_t set_ctx = {};
    bool tracked = false;
    const cuda_set_device_ctx_t *stored = bpf_map_lookup_elem(&cuda_set_device_ctx, &id);
    if (stored) {
        set_ctx.index = stored->index;
        tracked = true;
    }
    bpf_map_delete_elem(&cuda_set_device_ctx, &id);

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cudaSetDevice id=%llx ret=%d ===", id, ret);

    if (ret != 0 || !tracked) {
        return 0;
    }

    // A negative index is the "no device" sentinel; the thread is then bound to
    // nothing, which is what an absent entry means.
    if ((s32)set_ctx.index < 0) {
        bpf_map_delete_elem(&cuda_thread_device, &id);
        return 0;
    }

    bpf_map_update_elem(&cuda_thread_device, &id, &set_ctx.index, BPF_ANY);

    return 0;
}

// cudaGetDevice(int *device) for targets that only query the current device. It
// runs no introspection of its own, but restores a binding for a thread whose
// cudaSetDevice happened before instrumentation started.
SEC("uprobe/cudaGetDevice")
int BPF_KPROBE_GUARDED(obi_cuda_get_device, void *device) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaGetDevice id=%llx ===", id);

    capture_introspect(id, (u64)device, 0, 0, k_cuda_introspect_get);

    return 0;
}

SEC("uretprobe/cudaGetDevice")
int BPF_KRETPROBE_GUARDED(obi_cuda_get_device_ret, int ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    cuda_introspect_ctx_t intro = {};
    const bool captured = consume_introspect(id, k_cuda_introspect_get, &intro);

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cudaGetDevice id=%llx ret=%d ===", id, ret);

    if (ret != 0 || !captured) {
        return 0;
    }

    int device = 0;
    if (bpf_probe_read_user(&device, sizeof(device), (const void *)intro.buf_addr) != 0) {
        return 0;
    }

    if (device < 0) {
        bpf_map_delete_elem(&cuda_thread_device, &id);
        return 0;
    }

    const u32 index = (u32)device;
    bpf_map_update_elem(&cuda_thread_device, &id, &index, BPF_ANY);

    return 0;
}

// cudaGetDeviceProperties(cudaDeviceProp *prop, int device) fills a struct whose
// model name and UUID members have had stable offsets since CUDA 10.
SEC("uprobe/cudaGetDeviceProperties")
int BPF_KPROBE_GUARDED(obi_cuda_get_device_properties, void *prop, int device) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || device < 0) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaGetDeviceProperties id=%llx device=%d ===", id, device);

    capture_introspect(id, (u64)prop, (u32)device, 0, k_cuda_introspect_props);

    return 0;
}

SEC("uretprobe/cudaGetDeviceProperties")
int BPF_KRETPROBE_GUARDED(obi_cuda_get_device_properties_ret, int ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    cuda_introspect_ctx_t intro = {};
    const bool captured = consume_introspect(id, k_cuda_introspect_props, &intro);

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cudaGetDeviceProperties id=%llx ret=%d ===", id, ret);

    if (ret != 0 || !captured) {
        return 0;
    }

    merge_props(id, &intro);

    return 0;
}

SEC("uprobe/cudaGetDeviceProperties_v2")
int BPF_KPROBE_GUARDED(obi_cuda_get_device_properties_v2, void *prop, int device) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || device < 0) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaGetDeviceProperties_v2 id=%llx device=%d ===", id, device);

    capture_introspect(id, (u64)prop, (u32)device, 0, k_cuda_introspect_props);

    return 0;
}

SEC("uretprobe/cudaGetDeviceProperties_v2")
int BPF_KRETPROBE_GUARDED(obi_cuda_get_device_properties_v2_ret, int ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    cuda_introspect_ctx_t intro = {};
    const bool captured = consume_introspect(id, k_cuda_introspect_props, &intro);

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cudaGetDeviceProperties_v2 id=%llx ret=%d ===", id, ret);

    if (ret != 0 || !captured) {
        return 0;
    }

    merge_props(id, &intro);

    return 0;
}

// cuDeviceGetUuid(CUuuid *uuid, CUdevice dev) writes the 16 raw bytes that
// nvidia-smi renders after its "GPU-" prefix.
SEC("uprobe/cuDeviceGetUuid")
int BPF_KPROBE_GUARDED(obi_cu_device_get_uuid, void *uuid, int dev) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || dev < 0) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cuDeviceGetUuid id=%llx dev=%d ===", id, dev);

    capture_introspect(id, (u64)uuid, (u32)dev, 0, k_cuda_introspect_uuid);

    return 0;
}

SEC("uretprobe/cuDeviceGetUuid")
int BPF_KRETPROBE_GUARDED(obi_cu_device_get_uuid_ret, int ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    cuda_introspect_ctx_t intro = {};
    const bool captured = consume_introspect(id, k_cuda_introspect_uuid, &intro);

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cuDeviceGetUuid id=%llx ret=%d ===", id, ret);

    if (ret != 0 || !captured) {
        return 0;
    }

    u8 uuid[k_cuda_uuid_len] = {};
    if (bpf_probe_read_user(uuid, sizeof(uuid), (const void *)intro.buf_addr) != 0) {
        return 0;
    }

    merge_device_info(id, intro.index, k_device_has_uuid, uuid, NULL);

    return 0;
}

SEC("uprobe/cuDeviceGetUuid_v2")
int BPF_KPROBE_GUARDED(obi_cu_device_get_uuid_v2, void *uuid, int dev) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || dev < 0) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cuDeviceGetUuid_v2 id=%llx dev=%d ===", id, dev);

    capture_introspect(id, (u64)uuid, (u32)dev, 0, k_cuda_introspect_uuid);

    return 0;
}

SEC("uretprobe/cuDeviceGetUuid_v2")
int BPF_KRETPROBE_GUARDED(obi_cu_device_get_uuid_v2_ret, int ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    cuda_introspect_ctx_t intro = {};
    const bool captured = consume_introspect(id, k_cuda_introspect_uuid, &intro);

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cuDeviceGetUuid_v2 id=%llx ret=%d ===", id, ret);

    if (ret != 0 || !captured) {
        return 0;
    }

    u8 uuid[k_cuda_uuid_len] = {};
    if (bpf_probe_read_user(uuid, sizeof(uuid), (const void *)intro.buf_addr) != 0) {
        return 0;
    }

    merge_device_info(id, intro.index, k_device_has_uuid, uuid, NULL);

    return 0;
}

// cuDeviceGetName(char *name, int len, CUdevice dev) writes at most len bytes.
SEC("uprobe/cuDeviceGetName")
int BPF_KPROBE_GUARDED(obi_cu_device_get_name, void *name, int len, int dev) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || dev < 0 || len <= 0) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cuDeviceGetName id=%llx dev=%d len=%d ===", id, dev, len);

    capture_introspect(id, (u64)name, (u32)dev, (u32)len, k_cuda_introspect_name);

    return 0;
}

SEC("uretprobe/cuDeviceGetName")
int BPF_KRETPROBE_GUARDED(obi_cu_device_get_name_ret, int ret) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    cuda_introspect_ctx_t intro = {};
    const bool captured = consume_introspect(id, k_cuda_introspect_name, &intro);

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cuDeviceGetName id=%llx ret=%d ===", id, ret);

    if (ret != 0 || !captured) {
        return 0;
    }

    // The callee writes at most len bytes; the clamp both bounds the read for the
    // verifier and drops any name longer than we carry.
    const u32 read_len = intro.len < k_cuda_name_len ? intro.len : k_cuda_name_len;

    char name[k_cuda_name_len] = {};
    if (bpf_probe_read_user(name, read_len, (const void *)intro.buf_addr) != 0) {
        return 0;
    }

    merge_device_info(id, intro.index, k_device_has_name, NULL, name);

    return 0;
}
