// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/fd_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, fd_key); // key: fd
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} fd_to_connection SEC(".maps");
