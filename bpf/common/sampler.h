// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

// How a process samples traces: the OpenTelemetry Go SDK TraceIDRatioBased
// sampler, on its own or as the root of a ParentBased one. Every sampler OBI
// can be configured with takes this form. bpf2go exports it to pkg/ebpf/common.
typedef struct sampler {
    // a trace is sampled when its trace id ratio key is below the threshold
    u64 threshold;
    // a parent from another process decides for its children
    u8 parent_based;
    u8 _pad[7];
} sampler_t;
