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
    k_h2_push_promise_min_payload_len = 4,
    // highest frame type accepted; above this random bytes tile as framing too easily
    k_h2_max_extension_frame = 0x1f,
    // max frames walked when sniffing mid-stream H2
    k_h2_sniff_max_frames = 8,
    k_h2_max_payload = k_kprobes_http2_buf_size - k_h2_frame_header_len,
    // 33 tail-call budget: 7 hops per frame at worst, 5 plus 2 for its retry, 2 + 4*7 = 30
    k_h2_max_frames_per_packet = 4,
    k_h2_max_tp_retries = 2,
    k_h2_max_hpack_scan = 256,
    k_h2_default_max_frame_size = 16384,

    // --- W3C traceparent value layout: "00-<trace_id>-<span_id>-01" ---
    k_tp_val_dash1 = 2,
    k_tp_val_trace_id_start = k_tp_val_dash1 + 1,
    k_tp_val_dash2 = k_tp_val_trace_id_start + TRACE_ID_SIZE_BYTES * 2,
    k_tp_val_span_id_start = k_tp_val_dash2 + 1,
    k_tp_val_dash3 = k_tp_val_span_id_start + SPAN_ID_SIZE_BYTES * 2,

    // --- HPACK encoding ---
    k_hpack_literal_no_index = 0,       // RFC 7541 6.2.2
    k_hpack_literal_never_index = 0x10, // RFC 7541 6.2.3
    k_hpack_literal_incr_index = 0x40,  // RFC 7541 6.2.1
    k_hpack_size_update = 0x20,         // RFC 7541 6.3
    k_hpack_size_update_mask = 0xe0,
    k_hpack_int_prefix5 = 0x1f,  // 5-bit integer prefix, all ones means continuation follows
    k_hpack_int_more = 0x80,     // set in every continuation octet but the last
    k_hpack_int_max_octets = 5,  // RFC 7541 5.1: a u32 needs at most five octets past a prefix
    k_hpack_huffman_flag = 0x80, // set in a length byte when the string is huffman-encoded
    // two maximal size updates plus the opener, rounded up for index masking
    k_h2_hpack_opener_window = 16,
    k_h2_hpack_opener_mask = k_h2_hpack_opener_window - 1,
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

// PADDED/PRIORITY bytes that sit between the frame header and the HPACK block
static __always_inline u32 h2_hpack_prefix_len(u8 flags) {
    return ((flags & k_h2_flag_padded) ? 1 : 0) +
           ((flags & k_h2_flag_priority) ? k_h2_priority_prefix_len : 0);
}

// Only these three literal forms carry a new name inline.
static __always_inline u8 h2_hpack_is_literal(u8 b) {
    return b == k_hpack_literal_no_index || b == k_hpack_literal_never_index ||
           b == k_hpack_literal_incr_index;
}

static __always_inline u8 h2_hpack_is_size_update(u8 b) {
    return (b & k_hpack_size_update_mask) == k_hpack_size_update;
}

// Length of the size update at w[i], continuation octets included.
static __always_inline u32 h2_hpack_size_update_len(const unsigned char *w, u32 i, u32 have) {
    const u8 prefix = w[i & k_h2_hpack_opener_mask];

    if ((prefix & k_hpack_int_prefix5) != k_hpack_int_prefix5) {
        return 1; // the value fit the prefix, nothing follows it
    }

    // walk the continuation octets: all but the last carry k_hpack_int_more
    u32 octets = 1;

    while (octets < k_hpack_int_max_octets && i + octets < have &&
           (w[(i + octets) & k_h2_hpack_opener_mask] & k_hpack_int_more)) {
        octets++;
    }

    return 1 + octets;
}

// Offset of the first field in w, past any leading dynamic table size updates. Callers pass a
// stack window so the index stays maskable; the result can exceed have on a truncated window.
static __always_inline u32 h2_hpack_skip_size_updates(const unsigned char *w, u32 have) {
    u32 i = 0;

    // RFC 7541 4.2 allows two
    if (i < have && h2_hpack_is_size_update(w[i & k_h2_hpack_opener_mask])) {
        i += h2_hpack_size_update_len(w, i, have);
    }
    if (i < have && h2_hpack_is_size_update(w[i & k_h2_hpack_opener_mask])) {
        i += h2_hpack_size_update_len(w, i, have);
    }

    return i;
}

// Request blocks open with a pseudo-header: static index 1-7 (indexed or as a name ref), or
// a dyn-table index >= 62 once the encoder is warm. Responses open with :status, index 8-14.
static __always_inline u8 h2_hpack_opens_request(u8 b) {
    enum {
        k_hpack_req_pseudo_first = 1,
        k_hpack_req_pseudo_last = 7,
        k_hpack_dyn_table_first = 62,
        k_hpack_indexed = 0x80,
    };

    if (b & k_hpack_indexed) {
        const u8 idx = b & ~(u8)k_hpack_indexed;

        return (idx >= k_hpack_req_pseudo_first && idx <= k_hpack_req_pseudo_last) ||
               idx >= k_hpack_dyn_table_first;
    }

    // literal with a name reference: the index shares the low bits in every form
    const u8 idx = b & ~(u8)(k_hpack_literal_incr_index | k_hpack_literal_never_index);
    const u8 form = b & (u8)(k_hpack_literal_incr_index | k_hpack_literal_never_index);

    if (idx < k_hpack_req_pseudo_first || idx > k_hpack_req_pseudo_last) {
        return 0;
    }

    return form == k_hpack_literal_incr_index || form == k_hpack_literal_never_index ||
           form == k_hpack_literal_no_index;
}

// Responses open with :status: static index 8-14, indexed or as a name ref.
static __always_inline u8 h2_hpack_opens_response(u8 b) {
    enum {
        k_hpack_status_first = 8,
        k_hpack_status_last = 14,
        k_hpack_indexed = 0x80,
    };

    if (b & k_hpack_indexed) {
        const u8 idx = b & ~(u8)k_hpack_indexed;

        return idx >= k_hpack_status_first && idx <= k_hpack_status_last;
    }

    // every static entry 8-14 names :status, so any of them can be the name ref for a
    // non-200 status; the index shares the low bits in every literal form
    const u8 idx = b & ~(u8)(k_hpack_literal_incr_index | k_hpack_literal_never_index);
    const u8 form = b & (u8)(k_hpack_literal_incr_index | k_hpack_literal_never_index);

    if (idx < k_hpack_status_first || idx > k_hpack_status_last) {
        return 0;
    }

    return form == k_hpack_literal_incr_index || form == k_hpack_literal_never_index ||
           form == k_hpack_literal_no_index;
}

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
    if (length > k_h2_max_frame_len || r_bit) {
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
        // zero-length DATA is a half-close
        if ((flags & ~(u8)(k_h2_flag_end_stream | k_h2_flag_padded)) || !stream_id ||
            (!length && !(flags & k_h2_flag_end_stream))) {
            return 0;
        }
        break;
    case k_h2_frame_headers:
        // client-initiated stream IDs are odd-numbered (RFC 7540 5.1.1)
        if ((flags & ~(u8)(k_h2_flag_end_stream | k_h2_flag_end_headers | k_h2_flag_priority |
                           k_h2_flag_padded)) ||
            !(stream_id & 1) || !length) {
            return 0;
        }
        st->seen_headers = 1;
        st->expect_continuation = !(flags & k_h2_flag_end_headers);
        st->continuation_stream = stream_id;
        break;
    case k_h2_frame_push_promise:
        if ((flags & ~(u8)(k_h2_flag_end_headers | k_h2_flag_padded)) || !stream_id ||
            length < k_h2_push_promise_min_payload_len) {
            return 0;
        }
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
        if ((flags & ~(u8)k_h2_flag_ack) || stream_id || (length % k_h2_settings_entry_len) ||
            ((flags & k_h2_flag_ack) && length)) {
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
        if ((flags & ~(u8)k_h2_flag_end_headers) || (!length && !(flags & k_h2_flag_end_headers))) {
            return 0;
        }
        st->expect_continuation = !(flags & k_h2_flag_end_headers);
        break;
    default:
        // RFC 7540 4.1: unknown types are ignorable framing (PRIORITY_UPDATE, ALTSVC)
        if (type > k_h2_max_extension_frame) {
            return 0;
        }
        break;
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
