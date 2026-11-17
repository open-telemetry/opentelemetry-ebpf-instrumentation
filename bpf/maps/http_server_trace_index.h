// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_types.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

typedef struct http_server_trace_key {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    u32 pid;
} http_server_trace_key_t;

typedef struct http_server_trace_ref {
    http2_conn_stream_t stream;
    u32 _pad0;
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    u32 ambiguous;
    u32 _pad1;
} __attribute__((aligned(8))) http_server_trace_ref_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, http_server_trace_key_t);
    __type(value, http_server_trace_ref_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} http_server_trace_index SEC(".maps");
