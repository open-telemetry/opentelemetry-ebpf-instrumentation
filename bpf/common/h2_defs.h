// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/http_buf_size.h>
#include <common/tp_info.h>

// HTTP/2 and HPACK constants (RFC 7540, RFC 7541)
enum {
    // --- HTTP/2 framing ---
    k_h2_frame_header_len = 9,
    k_h2_frame_headers = 1,
    k_h2_flag_end_headers = 4,
    k_h2_flag_padded = 8,
    k_h2_flag_priority = 0x20,
    k_h2_priority_prefix_len = 5,
    k_h2_preface_len = 24,
    k_h2_preface_check_len = 4,
    k_h2_max_frame_len = 65535,
    k_h2_max_frame_scan = 4,
    k_h2_max_payload = k_kprobes_http2_buf_size - k_h2_frame_header_len,
    // Capped by the 33 tail-call budget (≤5 hops per frame).
    k_h2_max_frames_per_packet = 6,
    k_h2_max_hpack_scan = 192,
    k_h2_default_max_frame_size = 16384,

    // --- W3C traceparent value layout: "00-<trace_id>-<span_id>-01" ---
    k_tp_val_dash1 = 2,
    k_tp_val_trace_id_start = k_tp_val_dash1 + 1,
    k_tp_val_dash2 = k_tp_val_trace_id_start + TRACE_ID_SIZE_BYTES * 2,
    k_tp_val_span_id_start = k_tp_val_dash2 + 1,
    k_tp_val_dash3 = k_tp_val_span_id_start + SPAN_ID_SIZE_BYTES * 2,

    // --- HPACK encoding ---
    k_hpack_literal_no_index = 0,
    k_hpack_tp_name_len = 11,                  // strlen("traceparent")
    k_hpack_tp_name_huffman_len = 8,           // huffman-encoded "traceparent"
    k_hpack_tp_name_offset = 2,                // 1 byte literal flag + 1 byte name-len field
    k_hpack_value_len_tp = k_tp_val_dash3 + 3, // remaining "-01" suffix
    k_hpack_tp_val_offset = k_hpack_tp_name_offset + k_hpack_tp_name_len + 1,
    k_hpack_tp_val_offset_huffman = k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len + 1,
    k_hpack_tp_max_scan = 256 - k_h2_frame_header_len,

    // --- Full HPACK traceparent entry sizes ---
    k_h2_tp_hpack_size = k_hpack_tp_val_offset + k_hpack_value_len_tp,
    k_h2_tp_hpack_huffman_size = k_hpack_tp_val_offset_huffman + k_hpack_value_len_tp,
};

static const char k_hpack_tp_name[] = "traceparent";
// huffman-encoded "traceparent" (grpc-go HPACK encoder)
static const unsigned char k_hpack_tp_huffman[] = {0x4d, 0x83, 0x21, 0x6b, 0x1d, 0x85, 0xa9, 0x3f};
