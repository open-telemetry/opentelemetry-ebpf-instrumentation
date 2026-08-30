// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <pid/types/pid_info.h>

struct python_runtime_metric_target {
    u64 runtime_addr;
    u64 generation;
    u64 runtime_finalizing;
    u64 runtime_interpreters_main;
    u64 interpreter_gc;
    u64 gc_generation_stats;
};

struct python_gc_generation_metrics {
    u64 collections;
    u64 collected;
    u64 uncollectable;
};

struct python_runtime_metric_snapshot {
    u64 generation;
    struct python_gc_generation_metrics generations[3];
};

struct python_runtime_metric_event {
    u8 type;
    u8 _pad[3];
    pid_info pid;
    struct python_runtime_metric_snapshot snapshot;
};
