// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/http_types.h>

static __always_inline int capture_http_request_buffer(http_info_t *info,
                                                       const call_protocol_args_t *args) {
    u32 capture_len = (u32)args->bytes_len;
    bpf_clamp_umax(capture_len, sizeof(info->buf));

    const int err = bpf_probe_read(info->buf, capture_len, (void *)args->u_buf);
    if (err) {
        __builtin_memcpy(info->buf, args->small_buf, sizeof(args->small_buf));
    }

    return err;
}
