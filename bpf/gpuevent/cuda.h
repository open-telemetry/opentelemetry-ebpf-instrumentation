// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Source: https://github.com/facebookincubator/strobelight/blob/5d84bcfdd9abccc615b45a390bfd7bba7097dc51/strobelight/src/profilers/gpuevent_snoop/bpf/gpuevent_snoop.hO

// Copyright (c) Meta Platforms, Inc. and affiliates.
// Copyright Grafana Labs
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
#pragma once

#include <pid/types/pid_info.h>

// cudaUUID_t as embedded in cudaDeviceProp: the raw 16 bytes of a device UUID,
// the same bytes nvidia-smi renders after its "GPU-" prefix.
enum { k_cuda_uuid_len = 16 };

// Longest device model name we carry (for example "NVIDIA H20-3e").
// cudaDeviceProp.name is char[256], which no shipping device comes close to.
enum { k_cuda_name_len = 64 };

// Offsets of the name and UUID inside the cudaDeviceProp struct that
// cudaGetDeviceProperties fills in. The struct grows at the end with every CUDA
// release, but its first members have been stable since CUDA 10: the model name
// in a char[256], immediately followed by the device UUID.
enum { k_cuda_prop_name_off = 0 };
enum { k_cuda_prop_uuid_off = 256 };

// Identifies the device an observed CUDA call ran on. The index is the
// process-local device number (remapped by CUDA_VISIBLE_DEVICES), while the UUID
// identifies the physical device across the whole host. known is set only when
// the calling thread's current device was actually observed via cudaSetDevice or
// cudaGetDevice; otherwise the index and UUID are not meaningful.
typedef struct cuda_device {
    u32 index;
    u8 uuid[k_cuda_uuid_len];
    u8 known;
    u8 _pad[3]; // Trailing padding, so the events ending in this struct need none of their own
} cuda_device_t;

// Device identity learned from the CUDA introspection APIs. The model name only
// travels here, on the rare device events, never on the per-call events.
typedef struct cuda_device_info {
    u8 uuid[k_cuda_uuid_len];
    char name[k_cuda_name_len];
} cuda_device_info_t;

// Keys the device identity table. Device indices are only unique within a
// process, so the tgid is part of the key.
typedef struct cuda_device_key {
    u64 tgid;
    u32 index;
    u32 _pad;
} cuda_device_key_t;

// Per-thread context captured at cudaSetDevice entry and consumed at return so a
// failed call does not bind the thread to a device it never selected.
typedef struct cuda_set_device_ctx {
    u32 index;
} cuda_set_device_ctx_t;

// Which introspection API a device context was captured for. The receiving
// buffer and the device argument live in different places depending on the call.
enum cuda_introspect_kind {
    k_cuda_introspect_props = 1, // cudaGetDeviceProperties(device, prop)
    k_cuda_introspect_uuid = 2,  // cuDeviceGetUuid(uuid, dev)
    k_cuda_introspect_name = 3,  // cuDeviceGetName(name, len, dev)
    k_cuda_introspect_get = 4,   // cudaGetDevice(device)
};

// Per-thread context captured at the entry of an introspection call and consumed
// at its return, once the callee has written into the receiving buffer.
typedef struct cuda_introspect_ctx {
    u64 buf_addr;
    u32 index;
    u32 len;
    u32 kind;
    u32 _pad;
} cuda_introspect_ctx_t;

// Device identity as learned by the introspection APIs, reported for the device
// index it was resolved for. Userspace caches these by UUID to name the device
// on the per-call metrics.
typedef struct cuda_device_event {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 _pad[3];
    pid_info pid_info;
    u32 index;
    u8 uuid[k_cuda_uuid_len];
    char name[k_cuda_name_len];
} cuda_device_event_t;

typedef struct cuda_kernel_launch {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 _pad[3];
    pid_info pid_info;
    u64 kern_func_off;
    int grid_x;
    int grid_y;
    int grid_z;
    int block_x;
    int block_y;
    int block_z;
    cuda_device_t device;
} cuda_kernel_launch_t;

typedef struct cuda_memcpy {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 kind;
    u8 _pad[2];
    pid_info pid_info;
    s64 size;
    cuda_device_t device;
} cuda_memcpy_t;

// Generic size-based event (malloc, free, memset, host register).
typedef struct cuda_size_event {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 _pad[3];
    pid_info pid_info;
    s64 size;
    cuda_device_t device;
} cuda_size_event_t;

// Generic call event (graph launch, stream create/destroy, event record/synchronize,
// stream synchronize, device synchronize).
typedef struct cuda_call_event {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 _pad[3];
    pid_info pid_info;
    cuda_device_t device;
} cuda_call_event_t;

// Per-thread context captured at cudaMalloc entry and consumed at return so the
// allocated device pointer can be correlated with its size for cudaFree byte tracking.
typedef struct cuda_malloc_ctx {
    u64 dev_ptr_addr;
    s64 size;
} cuda_malloc_ctx_t;

// Per-thread context captured at cudaFree entry and consumed at return so the
// free is only reported once the return code confirms the memory was released.
typedef struct cuda_free_ctx {
    u64 dev_ptr;
    s64 size;
} cuda_free_ctx_t;

// Identifies a tracked allocation by process and device pointer. Device
// pointers are only unique within a process, so the pointer alone cannot key
// the allocation map. The tgid (not the full pid_tgid) is used because any
// thread of the process may free memory another thread allocated.
typedef struct cuda_alloc_key {
    u64 tgid;
    u64 ptr;
} cuda_alloc_key_t;

// User-memory view of the driver API CUlaunchConfig passed to cuLaunchKernelEx:
// seven u32 grid/block dimensions plus sharedMemBytes, four bytes of padding,
// then the stream handle.
typedef struct cu_launch_config {
    u32 grid_x;
    u32 grid_y;
    u32 grid_z;
    u32 block_x;
    u32 block_y;
    u32 block_z;
    u32 shared_mem_bytes;
    u32 _pad;
    u64 stream;
} cu_launch_config_t;
