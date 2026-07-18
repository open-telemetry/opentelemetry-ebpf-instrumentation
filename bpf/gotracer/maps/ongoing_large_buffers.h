// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "common/connection_info.h"
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>

#include <gotracer/types/go_large_buffer_req.h>
#include <gotracer/types/net_args.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, connection_info_t); // sorted connection info
    __type(value, u8);              // client or server request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ongoing_large_buffers SEC(".maps");