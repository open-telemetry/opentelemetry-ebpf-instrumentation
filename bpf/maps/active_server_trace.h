// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/tp_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

// Process-level active server trace context, keyed by tgid (process ID).
// Used as a fallback in find_parent_trace() when the sock_msg program fires
// on a different thread (e.g. an I/O thread in Python grpcio, Rust tonic,
// or Node.js) than the one that handled the incoming server request.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);             // key: tgid (process ID)
    __type(value, tp_info_pid_t); // value: traceparent info from incoming request
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} active_server_trace SEC(".maps");
