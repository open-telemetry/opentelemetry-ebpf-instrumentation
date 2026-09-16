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
// be correlated with its size for byte-accurate cudaFree metrics.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, cuda_malloc_ctx_t);
} cuda_malloc_ctx SEC(".maps");

// Maps an allocated device pointer to its size. Populated by the cudaMalloc
// uretprobe and consumed by the cudaFree uprobe.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, s64);
} cuda_alloc_sizes SEC(".maps");

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

SEC("uprobe/cudaLaunchKernel")
int BPF_KPROBE_GUARDED(
    obi_cuda_launch, u64 func_off, u64 grid_xy, u64 grid_z, u64 block_xy, u64 block_z) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaLaunchKernel id=%llx ===", id);

    cuda_kernel_launch_t *e = bpf_ringbuf_reserve(&gpu_events, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return 0;
    }

    e->flags = k_event_kernel_launch;
    task_pid(&e->pid_info);

    e->kern_func_off = func_off;
    e->grid_x = (u32)grid_xy;
    e->grid_y = (u32)(grid_xy >> 32);
    e->grid_z = (u32)grid_z;
    e->block_x = (u32)block_xy;
    e->block_y = (u32)(block_xy >> 32);
    e->block_z = (u32)block_z;

    bpf_ringbuf_submit(e, 0);
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

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe/cudaMalloc id=%llx ret=%d ===", id, ret);

    if (ret != 0) {
        bpf_map_delete_elem(&cuda_malloc_ctx, &id);
        return 0;
    }

    cuda_malloc_ctx_t *malloc_ctx = bpf_map_lookup_elem(&cuda_malloc_ctx, &id);
    if (!malloc_ctx) {
        return 0;
    }

    void *dev_ptr = NULL;
    if (bpf_probe_read_user(&dev_ptr, sizeof(dev_ptr), (void *)malloc_ctx->dev_ptr_addr) != 0) {
        bpf_map_delete_elem(&cuda_malloc_ctx, &id);
        return 0;
    }

    const u64 ptr_val = (u64)dev_ptr;
    if (ptr_val != 0) {
        bpf_map_update_elem(&cuda_alloc_sizes, &ptr_val, &malloc_ctx->size, BPF_ANY);
    }
    bpf_map_delete_elem(&cuda_malloc_ctx, &id);

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

    const u64 ptr_val = (u64)devPtr;
    s64 *size = bpf_map_lookup_elem(&cuda_alloc_sizes, &ptr_val);
    if (!size) {
        // Pointer was not allocated through cudaMalloc (or tracking was lost);
        // do not emit a byte metric for it.
        return 0;
    }

    submit_size_event(k_event_free, *size);
    bpf_map_delete_elem(&cuda_alloc_sizes, &ptr_val);

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
