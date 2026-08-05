// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/hpack.h>
#include <common/http_types.h>

#include <generictracer/types/http2_server_hpack_lease.h>

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

    u32 server_tp_offset;
    u32 server_tp_encoded_len;
    u8 server_tp_huffman;
    u8 server_hpack_base;
    u8 server_hpack_lease_active;
    u8 server_hpack_force_root;
    u8 server_hpack_maintenance;
    u8 server_hpack_inserted_slot;
    u8 server_hpack_inserted_generation;
    u8 server_hpack_cache_store_pending;
    u8 server_hpack_fail_closed;
    u8 server_hpack_resume_pending;
    u8 server_hpack_blocks;
    u8 _server_pad[1];
    u64 server_hpack_lease_token;
    http2_server_hpack_lease_key_t server_hpack_lease_key;
    // The lease key above is transaction-local and is overwritten by the
    // next block. Keep an immutable generation fence for bytes that remain in
    // the current callback after END_HEADERS.
    http2_server_hpack_lease_key_t server_hpack_resume_key;
    hpack_traceparent_scan_state_t server_hpack_scan;
    hpack_traceparent_decoder_state_t server_hpack_decoder;
    u8 _pad_end[4];
} grpc_frames_ctx_t;
