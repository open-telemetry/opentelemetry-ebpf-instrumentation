// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/backup_buffer.h>
#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, connection_info_t);
    __type(value, backup_buffer_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} sock_filter_buffers SEC(".maps");
