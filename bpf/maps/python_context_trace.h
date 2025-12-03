// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/trace_key.h>
#include <common/pin_internal.h>
#include <common/map_sizing.h>

// Maps a Python context pointer to the trace_key_t of the server span that
// was active when the context was created.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);           // Python context pointer (PyObject*)
    __type(value, trace_key_t); // Server parent trace key
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_context_trace SEC(".maps");
