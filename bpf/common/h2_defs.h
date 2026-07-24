// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_buf_size.h>
#include <common/tp_info.h>

// HTTP/2 and HPACK constants (RFC 7540, RFC 7541)
enum {
    // --- HTTP/2 framing ---
    k_h2_frame_header_len = 9,
    k_h2_frame_stream_id_offset = k_h2_frame_header_len - sizeof(u32),
    k_h2_frame_data = 0,
    k_h2_frame_headers = 1,
    k_h2_frame_priority = 2,
    k_h2_frame_rst_stream = 3,
    k_h2_frame_settings = 4, // RFC 7540 §6.5 SETTINGS frame type
    k_h2_frame_push_promise = 5,
    k_h2_frame_ping = 6,
    k_h2_frame_goaway = 7,
    k_h2_frame_window_update = 8,
    k_h2_frame_continuation = 9,
    k_h2_flag_end_stream = 1,
    k_h2_flag_ack = 1,
    k_h2_flag_end_headers = 4,
    k_h2_flag_padded = 8,
    k_h2_flag_priority = 0x20,
    k_h2_priority_prefix_len = 5,
    k_h2_preface_len = 24,
    k_h2_preface_check_len = 4,
    k_h2_max_frame_len = 65535,
    k_h2_max_frame_scan = 4,
    k_h2_reserved_bit_mask = 0x80,
    k_h2_priority_payload_len = 5,
    k_h2_rst_stream_payload_len = 4,
    k_h2_settings_entry_len = 6,
    k_h2_ping_payload_len = 8,
    k_h2_goaway_min_payload_len = 8,
    k_h2_window_update_payload_len = 4,
    // max frames walked when sniffing mid-stream H2
    k_h2_sniff_max_frames = 8,
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

// Shared state for the strict mid-stream H2 sniffers
typedef struct h2_sniff_state {
    u32 continuation_stream;
    u8 seen_headers;
    u8 expect_continuation;
    u8 _pad[2];
} h2_sniff_state_t;

// Strict RFC 7540 checks: misclassifying is worse than missing, reject what real stacks never emit
static __always_inline u8
h2_sniff_check_frame(h2_sniff_state_t *st, u32 length, u8 type, u8 flags, u8 r_bit, u32 stream_id) {
    if (length == 0 || length > k_h2_max_frame_len || r_bit) {
        return 0;
    }

    // CONTINUATION is legal only inside an open header block, on the same stream
    if (st->expect_continuation) {
        if (type != k_h2_frame_continuation || stream_id != st->continuation_stream) {
            return 0;
        }
    } else if (type == k_h2_frame_continuation) {
        return 0;
    }

    switch (type) {
    case k_h2_frame_data:
        if ((flags & ~(u8)k_h2_flag_end_stream) || !stream_id) {
            return 0;
        }
        break;
    case k_h2_frame_headers:
        // client-initiated stream IDs are odd-numbered (RFC 7540 5.1.1)
        if ((flags & ~(u8)(k_h2_flag_end_stream | k_h2_flag_end_headers | k_h2_flag_priority)) ||
            !(stream_id & 1)) {
            return 0;
        }
        st->seen_headers = 1;
        st->expect_continuation = !(flags & k_h2_flag_end_headers);
        st->continuation_stream = stream_id;
        break;
    case k_h2_frame_priority:
        if (flags || length != k_h2_priority_payload_len || !stream_id) {
            return 0;
        }
        break;
    case k_h2_frame_rst_stream:
        if (flags || length != k_h2_rst_stream_payload_len || !stream_id) {
            return 0;
        }
        break;
    case k_h2_frame_settings:
        if ((flags & ~(u8)k_h2_flag_ack) || stream_id || (length % k_h2_settings_entry_len)) {
            return 0;
        }
        break;
    case k_h2_frame_ping:
        if ((flags & ~(u8)k_h2_flag_ack) || stream_id || length != k_h2_ping_payload_len) {
            return 0;
        }
        break;
    case k_h2_frame_goaway:
        if (flags || stream_id || length < k_h2_goaway_min_payload_len) {
            return 0;
        }
        break;
    case k_h2_frame_window_update:
        if (flags || length != k_h2_window_update_payload_len) {
            return 0;
        }
        break;
    case k_h2_frame_continuation:
        if (flags & ~(u8)k_h2_flag_end_headers) {
            return 0;
        }
        st->expect_continuation = !(flags & k_h2_flag_end_headers);
        break;
    default: // PUSH_PROMISE and unknown types
        return 0;
    }

    return 1;
}

// Validates one raw 9-byte frame header, returns payload length via frame_len, 0 to reject
static __always_inline u8 h2_sniff_frame_header(h2_sniff_state_t *st,
                                                const unsigned char *d,
                                                u32 *frame_len) {
    *frame_len = ((u32)d[0] << 16) | ((u32)d[1] << 8) | (u32)d[2];
    const u32 stream_id = (((u32)(d[5] & ~(u8)k_h2_reserved_bit_mask) << 24) | ((u32)d[6] << 16) |
                           ((u32)d[7] << 8) | (u32)d[8]);
    return h2_sniff_check_frame(
        st, *frame_len, d[3], d[4], d[5] & k_h2_reserved_bit_mask, stream_id);
}

// H2 only if frames tiled the buffer exactly, with a HEADERS frame and no open header block
static __always_inline u8 h2_sniff_accept(const h2_sniff_state_t *st, u32 pos, u32 buf_len) {
    return pos == buf_len && st->seen_headers && !st->expect_continuation;
}
