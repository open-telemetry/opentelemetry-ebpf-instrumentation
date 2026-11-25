// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

typedef struct goroutine_metadata_t {
    go_addr_key_t parent;
    u64 timestamp;
} goroutine_metadata;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);        // key: pointer to the goroutine
    __type(value, goroutine_metadata); // value: timestamp of the goroutine creation
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ongoing_goroutines SEC(".maps");
