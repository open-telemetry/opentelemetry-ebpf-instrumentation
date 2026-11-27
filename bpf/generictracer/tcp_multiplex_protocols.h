// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/http_types.h>
#include <generictracer/protocol_iso8583.h>

// This filter opts a TCP record into per-operation capture. Userspace selects the
// decoder only after the regular TCP classifiers see the complete exchange.
static __always_inline bool tcp_multiplex_candidate(const call_protocol_args_t *args) {
    return iso8583_framed_write(args->small_buf, args->bytes_len);
}
