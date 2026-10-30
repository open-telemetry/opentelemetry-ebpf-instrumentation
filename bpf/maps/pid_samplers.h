// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/sampler.h>

enum { k_max_pid_samplers = 1 << 14 };

// The sampler of each instrumented process, keyed by the pid OBI's /proc numbers
// it with. Processes sampled as parentbased_always_on, the default, have no entry.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_max_pid_samplers);
    __type(key, u32);
    __type(value, sampler_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} pid_samplers SEC(".maps");
