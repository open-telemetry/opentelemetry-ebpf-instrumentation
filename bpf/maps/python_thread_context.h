// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/trace_key.h>
#include <common/map_sizing.h>

// Maps thread ID (trace_key_t) to the Python context pointer currently
// running on that thread.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, trace_key_t);
    __type(value, u64); // Python context pointer (PyObject*)
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_thread_context SEC(".maps");
