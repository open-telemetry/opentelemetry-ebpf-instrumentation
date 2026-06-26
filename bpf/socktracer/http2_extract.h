// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>
#include <common/h2_hpack.h>
#include <common/http_types.h>

#include <socktracer/common_defs.h>

// Bytes pulled for the scan. The injector appends the traceparent at the HEADERS
// frame boundary, which for a full gRPC request sits a few hundred bytes in.
enum { k_h2_ingress_pull = 512 };

// Decode the traceparent at position p (already fingerprint-matched) into *out.
static __always_inline bool
h2_decode_plain_at(const unsigned char *p, const unsigned char *end, tp_info_t *out) {
    if ((void *)(p + k_h2_tp_hpack_size) > (void *)end) {
        return false;
    }
    if (p[0] != k_hpack_literal_no_index || p[1] != k_h2_nlb_plain || !match_h2_tp_plain(p)) {
        return false;
    }
    return try_parse_tp_value(&p[k_hpack_tp_val_offset], out) != 0;
}

static __always_inline bool
h2_decode_huffman_at(const unsigned char *p, const unsigned char *end, tp_info_t *out) {
    if ((void *)(p + k_h2_tp_hpack_huffman_size) > (void *)end) {
        return false;
    }
    if (p[0] != k_hpack_literal_no_index || p[1] != k_h2_nlb_huffman || !match_h2_tp_huffman(p)) {
        return false;
    }
    return try_parse_tp_value(&p[k_hpack_tp_val_offset_huffman], out) != 0;
}

// Adopt an incoming HTTP/2 request's traceparent by reading the packet DIRECTLY
// (no copy), socktracer's native model (same as HTTP/1 and the egress scan).
// Two complementary, verifier-cheap probes over live packet data:
//   1. the HEADERS frame boundary, where injectors (socktracer/tpinjector/
//      gotracer) append the traceparent — reachable at any depth via the frame
//      length, where a bounded from-start scan can't reach;
//   2. a bounded general scan from the start for traceparents placed earlier.
// Decodes trace_id + parent_id into *out using the shared HPACK helpers.
static __always_inline bool scan_h2_ingress_tp(void *ctx, tp_info_t *out) {
    ctx_pull_data(ctx, k_h2_ingress_pull);

    const unsigned char *data = ctx_data(ctx);
    const unsigned char *end = ctx_data_end(ctx);

    if (!data || (void *)(data + k_h2_frame_header_len) > (void *)end) {
        return false;
    }

    // (1) Frame-boundary probe: a leading HEADERS frame whose appended traceparent
    // ends exactly at the frame boundary. The frame must fit in the pulled window.
    if (data[3] == k_h2_frame_headers) {
        const u32 payload_len = ((u32)data[0] << 16) | ((u32)data[1] << 8) | (u32)data[2];

        if (payload_len <= k_h2_ingress_pull - k_h2_frame_header_len) {
            const u32 frame_end = k_h2_frame_header_len + payload_len;

            if (frame_end >= k_h2_tp_hpack_size &&
                h2_decode_plain_at(data + (frame_end - k_h2_tp_hpack_size), end, out)) {
                return true;
            }
            if (frame_end >= k_h2_tp_hpack_huffman_size &&
                h2_decode_huffman_at(data + (frame_end - k_h2_tp_hpack_huffman_size), end, out)) {
                return true;
            }
        }
    }

    // (2) Bounded general scan from the start.
    for (u32 i = 0; i < k_h2_max_hpack_scan; i++) {
        const unsigned char *p = data + i;

        if ((void *)(p + k_h2_tp_hpack_huffman_size) > (void *)end) {
            break;
        }

        if (p[0] != k_hpack_literal_no_index) {
            continue;
        }

        const u8 nlb = p[1];

        if (nlb == k_h2_nlb_plain && h2_decode_plain_at(p, end, out)) {
            return true;
        }
        if (nlb == k_h2_nlb_huffman && h2_decode_huffman_at(p, end, out)) {
            return true;
        }
    }

    return false;
}
