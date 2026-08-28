// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <generictracer/types/python_runtime.h>
#include <pid/maps/map_sizing.h>
#include <pid/types/pid_info.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_max_concurrent_pids);
    __type(key, pid_info);
    __type(value, struct python_runtime_metric_target);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_runtime_metric_targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_max_concurrent_pids);
    __type(key, pid_info);
    __type(value, struct python_runtime_metric_snapshot);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_runtime_metric_snapshots SEC(".maps");
