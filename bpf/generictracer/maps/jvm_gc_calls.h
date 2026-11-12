// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <common/pin_internal.h>
#include <generictracer/types/jvm.h>

// Keyed by pid_tgid of the thread running a HotSpot GC phase
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct jvm_gc_call);
    __uint(pinning, OBI_PIN_INTERNAL);
} jvm_gc_calls SEC(".maps");
