// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>

#include <gotracer/types/go_large_buffer_req.h>
#include <gotracer/types/go_large_buffer_key.h>
#include <gotracer/types/net_args.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_large_buffer_key_t);   // sorted connection info
    __type(value, go_large_buffer_req_t); // client or server request with traceparent
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ongoing_large_buffers SEC(".maps");