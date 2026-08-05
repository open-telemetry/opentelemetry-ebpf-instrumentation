// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>

#include <generictracer/types/http2_server_hpack_lease.h>
#include <generictracer/types/http2_server_hpack_state.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, http2_server_hpack_lease_key_t);
    __type(value, http2_server_hpack_state_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} http2_server_hpack_states SEC(".maps");

SCRATCH_MEM_TYPED(http2_server_hpack_state, http2_server_hpack_state_t)
