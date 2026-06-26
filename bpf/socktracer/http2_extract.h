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
enum {
    k_h2_ingress_pull = 512,
    // Cap on a leading SETTINGS frame's payload when locating HEADERS behind the
    // connection preface, so the computed offset stays bounded for the verifier.
    k_h2_ingress_settings_max = 64,
};

// Decode the traceparent at position p (already fingerprint-matched) into *out.
// Uses decode_tp_value (incoming span -> out->span_id), not try_parse_tp_value
// (-> parent_id): socktracer routes this tp through init_tp, which derives the
// server span's parent from parent_tp->span_id. (The generictracer applies its tp
// directly, so it wants parent_id — same bytes, different target field.)
static __always_inline bool
h2_decode_plain_at(const unsigned char *p, const unsigned char *end, tp_info_t *out) {
    if ((void *)(p + k_h2_tp_hpack_size) > (void *)end) {
        return false;
    }
    if (p[0] != k_hpack_literal_no_index || p[1] != k_h2_nlb_plain || !match_h2_tp_plain(p)) {
        return false;
    }
    return decode_tp_value(&p[k_hpack_tp_val_offset], out);
}

static __always_inline bool
h2_decode_huffman_at(const unsigned char *p, const unsigned char *end, tp_info_t *out) {
    if ((void *)(p + k_h2_tp_hpack_huffman_size) > (void *)end) {
        return false;
    }
    if (p[0] != k_hpack_literal_no_index || p[1] != k_h2_nlb_huffman || !match_h2_tp_huffman(p)) {
        return false;
    }
    return decode_tp_value(&p[k_hpack_tp_val_offset_huffman], out);
}

// Probe a HEADERS frame at byte offset `off`: the injector appends the traceparent
// as the last HPACK entry, so it ends at the frame boundary. Checks that exact slot
// (plaintext, then huffman). `off` must be bounded by the caller.
static __always_inline bool
h2_probe_headers_at(const unsigned char *data, u32 off, const unsigned char *end, tp_info_t *out) {
    if ((void *)(data + off + k_h2_frame_header_len) > (void *)end) {
        return false;
    }
    if (data[off + 3] != k_h2_frame_headers) {
        return false;
    }

    const u32 payload_len =
        ((u32)data[off] << 16) | ((u32)data[off + 1] << 8) | (u32)data[off + 2];

    if (payload_len > k_h2_ingress_pull) {
        return false;
    }

    const u32 frame_end = off + k_h2_frame_header_len + payload_len;

    if (frame_end >= k_h2_tp_hpack_size &&
        h2_decode_plain_at(data + (frame_end - k_h2_tp_hpack_size), end, out)) {
        return true;
    }
    if (frame_end >= k_h2_tp_hpack_huffman_size &&
        h2_decode_huffman_at(data + (frame_end - k_h2_tp_hpack_huffman_size), end, out)) {
        return true;
    }

    return false;
}

// Adopt an incoming HTTP/2 request's traceparent by reading the packet DIRECTLY
// (no copy), socktracer's native model (same as HTTP/1 and the egress scan).
// Three complementary, verifier-cheap probes over live packet data:
//   1. a leading HEADERS frame's boundary (steady-state requests);
//   2. a HEADERS frame behind the coalesced preface + SETTINGS (first request on a
//      connection — gRPC clients send preface+SETTINGS+HEADERS in one packet);
//   3. a bounded general scan from the start for traceparents placed earlier.
// Decodes trace_id + parent_id into *out using the shared HPACK helpers.
static __always_inline bool scan_h2_ingress_tp(void *ctx, tp_info_t *out) {
    ctx_pull_data(ctx, k_h2_ingress_pull);

    const unsigned char *data = ctx_data(ctx);
    const unsigned char *end = ctx_data_end(ctx);

    if (!data || (void *)(data + k_h2_frame_header_len) > (void *)end) {
        return false;
    }

    // (1) HEADERS leads the packet.
    if (h2_probe_headers_at(data, 0, end, out)) {
        return true;
    }

    // (2) preface + SETTINGS + HEADERS coalesced (first request on a connection).
    if ((void *)(data + k_h2_preface_len + k_h2_frame_header_len) <= (void *)end &&
        data[0] == 'P' && data[1] == 'R' && data[2] == 'I' && data[3] == ' ') {
        const u32 settings_len = ((u32)data[k_h2_preface_len] << 16) |
                                 ((u32)data[k_h2_preface_len + 1] << 8) |
                                 (u32)data[k_h2_preface_len + 2];
        if (settings_len <= k_h2_ingress_settings_max) {
            const u32 hdr_off = k_h2_preface_len + k_h2_frame_header_len + settings_len;
            if (h2_probe_headers_at(data, hdr_off, end, out)) {
                return true;
            }
        }
    }

    // (3) bounded general scan from the start.
    for (u32 i = 0; i < k_h2_max_hpack_scan; i++) {
        const unsigned char *p = data + i;

        if ((void *)(p + k_h2_tp_hpack_huffman_size) > (void *)end) {
            break;
        }

        if (p[0] != k_hpack_literal_no_index) {
            continue;
        }

        const u8 nlb = p[1];

        if (nlb == k_h2_nlb_plain && match_h2_tp_plain(p)) {
            if ((void *)(p + k_h2_tp_hpack_size) > (void *)end) {
                break;
            }
            if (decode_tp_value(&p[k_hpack_tp_val_offset], out)) {
                return true;
            }
        } else if (nlb == k_h2_nlb_huffman && match_h2_tp_huffman(p)) {
            if (decode_tp_value(&p[k_hpack_tp_val_offset_huffman], out)) {
                return true;
            }
        }
    }

    return false;
}
