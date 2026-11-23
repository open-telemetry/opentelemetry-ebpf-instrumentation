// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/sampler.h>

#include <pid/types/pid_info.h>

enum { k_max_pid_samplers = 1 << 14 };

// Keyed by {user_pid, ns}, with host_pid zero, like go_runtime_metric_targets.
// Processes sampled as parentbased_always_on, the default, have no entry.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_max_pid_samplers);
    __type(key, pid_info_t);
    __type(value, sampler_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} pid_samplers SEC(".maps");
