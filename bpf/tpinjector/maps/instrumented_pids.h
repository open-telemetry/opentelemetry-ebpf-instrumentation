// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <pid/types/pid_filter.h>

// laid out like valid_pids, which only holds the processes the generic tracer instruments
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, k_valid_pids_words);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} instrumented_pids SEC(".maps");
