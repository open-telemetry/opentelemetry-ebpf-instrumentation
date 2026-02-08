// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Source: https://github.com/facebookincubator/strobelight/blob/5d84bcfdd9abccc615b45a390bfd7bba7097dc51/strobelight/src/profilers/gpuevent_snoop/bpf/gpuevent_snoop.hO

// Copyright (c) Meta Platforms, Inc. and affiliates.
// Copyright Grafana Labs
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
#pragma once

#include <pid/pid.h>
#include <common/tp_info.h>

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
} cuda_kernel_launch_t;

typedef struct cuda_malloc {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 _pad[3];
    pid_info pid_info;
    s64 size;
} cuda_malloc_t;

typedef struct cuda_memcpy {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 kind;
    u8 _pad[2];
    pid_info pid_info;
    s64 size;
} cuda_memcpy_t;

typedef struct cuda_graph_launch {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 kind;
    u8 _pad[2];
    pid_info pid_info;
} cuda_graph_launch_t;