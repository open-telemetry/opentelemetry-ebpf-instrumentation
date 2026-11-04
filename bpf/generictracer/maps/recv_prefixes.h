// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <generictracer/recv_prefix.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, pid_connection_info_t);
    __type(value, recv_prefix_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} recv_prefixes SEC(".maps");
