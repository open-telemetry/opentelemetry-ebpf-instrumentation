// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>

// LRU map which holds onto the mapping of an ssl pointer to pid-tid,
// we clean-it up when we lookup by ssl. It's setup by SSL_read for cases where frameworks
// process SSL requests on separate thread pools, e.g. Ruby on Rails
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the ssl pointer
    __type(value, u64); // the pid tid of the thread in ssl read
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ssl_to_pid_tid SEC(".maps");
