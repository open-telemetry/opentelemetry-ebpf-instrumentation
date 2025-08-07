// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/http_types.h>

#include <generictracer/types/http2_conn_info_data.h>

typedef struct grpc_frames_ctx {
    http2_grpc_request_t prev_info;
    u8 has_prev_info;
    u8 found_data_frame;
    u8 iterations;
    u8 terminate_search;

    int pos; //FIXME should be size_t equivalent
    int saved_buf_pos;
    u32 saved_stream_id;
    call_protocol_args_t args;
    http2_conn_stream_t stream;

    u8 _pad[4];
} grpc_frames_ctx_t;
