// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/http1_traceparent.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

typedef struct http1_pending_headers {
    http1_header_scan_t scan;
    u32 request_head; // first bytes of the request, to recognise its corked message
    tp_info_pid_t client_tp;
    bool has_client_tp;
    bool pending;
    u8 cork_rounds;
    u8 _pad[5];
} http1_pending_headers_t;

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, http1_pending_headers_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} sk_http1_headers SEC(".maps");
