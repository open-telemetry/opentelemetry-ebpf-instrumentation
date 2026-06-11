// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <common/pin_internal.h>
#include <generictracer/types/jvm.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct jvm_heap_summary_key);
    __type(value, struct jvm_sample_value);
    __uint(pinning, OBI_PIN_INTERNAL);
} jvm_heap_summary_samples SEC(".maps");
