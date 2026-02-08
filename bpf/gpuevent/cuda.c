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

const cuda_kernel_launch_t *unused_gpu __attribute__((unused));
const cuda_malloc_t *unused_gpu1 __attribute__((unused));
const cuda_memcpy_t *unused_gpu2 __attribute__((unused));
const cuda_graph_launch_t *unused_gpu3 __attribute__((unused));

enum {
    k_event_kernel_launch = 1,
    k_event_malloc = 2,
    k_event_memcpy = 3,
    k_event_graph_launch = 4,
};

SEC("uprobe/cudaLaunchKernel")
int BPF_KPROBE(obi_cuda_launch, u64 func_off, u64 grid_xy, u64 grid_z, u64 block_xy, u64 block_z) {
    (void)ctx;
    u64 id = bpf_get_current_pid_tgid();

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
int BPF_KPROBE(obi_cuda_malloc, void **devPtr, size_t size) {
    (void)ctx;
    (void)devPtr;

    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaMalloc id=%llx ===", id);

    cuda_malloc_t *e = bpf_ringbuf_reserve(&gpu_events, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return 0;
    }

    e->flags = k_event_malloc;
    task_pid(&e->pid_info);
    e->size = (s64)size;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/cudaMemcpyAsync")
int BPF_KPROBE(obi_cuda_memcpy, void *dst, void *src, size_t size, u8 kind) {
    (void)ctx;
    (void)dst;
    (void)src;

    u64 id = bpf_get_current_pid_tgid();

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
int BPF_KPROBE(obi_graph_launch) {
    (void)ctx;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe/cudaGraphLaunch id=%llx ===", id);

    cuda_graph_launch_t *e = bpf_ringbuf_reserve(&gpu_events, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return 0;
    }

    e->flags = k_event_graph_launch;
    task_pid(&e->pid_info);

    bpf_ringbuf_submit(e, 0);
    return 0;
}