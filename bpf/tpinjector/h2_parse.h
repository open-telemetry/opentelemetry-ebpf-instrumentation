// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>

// Parsed HTTP/2 HEADERS frame at a given offset in an sk_msg packet.
// hpack_offset_in_msg / hpack_len delimit the actual HPACK header block
// (PADDED prefix and trailing pad bytes are excluded).
typedef struct {
    u32 stream_id;
    u32 payload_len;         // raw frame payload length (after 9-byte header)
    u32 hpack_offset_in_msg; // start of HPACK bytes inside the sk_msg
    u32 hpack_len;           // HPACK block length
    bool is_headers_end;     // true for HEADERS with END_HEADERS, payload_len > 0
    u8 ftype;                // raw HTTP/2 frame type byte
    u8 _pad[2];
} h2_frame_info_t;

// Parses the HTTP/2 frame header at `pos` inside `msg` and fills `out`.
// Returns:
//   1  → parse OK, `out` populated. Caller checks `out->is_headers_end` to
//        decide whether to act.
//   0  → giving up on this packet (out of bounds, oversized, malformed pad)
//
// Pulls only the bytes it needs (9 bytes; +1 more for PADDED). Each pull keeps
// the offset constant — the verifier rejects offsets that grow with the loop.
static __always_inline int
parse_h2_frame_at(struct sk_msg_md *msg, u32 pos, u32 msg_size, h2_frame_info_t *out) {
    if (pos + k_h2_frame_header_len > msg_size) {
        return 0;
    }
    if (bpf_msg_pull_data(msg, pos, pos + k_h2_frame_header_len, 0) != 0) {
        return 0;
    }
    unsigned char *d = msg->data;
    if (!d || (void *)d + k_h2_frame_header_len > msg->data_end) {
        return 0;
    }

    const u32 len = ((u32)d[0] << 16) | ((u32)d[1] << 8) | (u32)d[2];
    const u8 ftype = d[3];
    const u8 flags = d[4];
    if (len > k_h2_max_frame_len) {
        return 0;
    }

    out->payload_len = len;
    out->ftype = ftype;
    out->is_headers_end =
        (ftype == k_h2_frame_headers) && (flags & k_h2_flag_end_headers) && (len > 0);

    if (!out->is_headers_end) {
        return 1;
    }

    out->stream_id =
        (((u32)(d[5] & 0x7f) << 24) | ((u32)d[6] << 16) | ((u32)d[7] << 8) | (u32)d[8]);

    // RFC 7540 §6.2: PADDED/PRIORITY take bytes off the HPACK window
    u32 prefix = 0;
    u32 pad_len = 0;
    if (flags & k_h2_flag_padded) {
        if (pos + k_h2_frame_header_len + 1 > msg_size) {
            return 0;
        }
        if (bpf_msg_pull_data(msg, pos, pos + k_h2_frame_header_len + 1, 0) != 0) {
            return 0;
        }
        d = msg->data;
        if (!d || (void *)d + k_h2_frame_header_len + 1 > msg->data_end) {
            return 0;
        }
        pad_len = d[k_h2_frame_header_len];
        prefix += 1;
    }
    if (flags & k_h2_flag_priority) {
        prefix += k_h2_priority_prefix_len;
    }
    if (prefix + pad_len >= len) {
        return 0;
    }

    out->hpack_offset_in_msg = pos + k_h2_frame_header_len + prefix;
    out->hpack_len = len - prefix - pad_len;
    return 1;
}
