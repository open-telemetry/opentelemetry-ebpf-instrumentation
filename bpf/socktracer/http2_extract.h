// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>
#include <common/h2_hpack.h>
#include <common/http_types.h>

#include <socktracer/common_defs.h>

// Bytes pulled from the packet to inspect the leading HEADERS frame. Large enough
// for a typical gRPC request's headers; a frame that does not fit is skipped.
enum { k_h2_ingress_pull = 512 };

// Reads an incoming HTTP/2 request's traceparent from its HPACK headers into *out.
//
// The egress injector (obi_egress_h2_write_step) appends the traceparent as the
// final HPACK entry and patches the HEADERS frame length, so on the wire the
// entry ends exactly at the frame boundary. Reading the frame length and checking
// that single position avoids a large blind scan, which the verifier rejects
// (the 1M-instruction budget caps such a scan well short of where the entry can
// land). Returns true if a traceparent was found.
static __always_inline bool scan_h2_ingress_tp(void *ctx, tp_info_t *out) {
    ctx_pull_data(ctx, k_h2_ingress_pull);

    const unsigned char *data = ctx_data(ctx);
    const unsigned char *end = ctx_data_end(ctx);

    if (!data || (void *)(data + k_h2_frame_header_len) > (void *)end) {
        return false;
    }

    // Steady-state request packets start with the HEADERS frame. A packet that
    // leads with the preface/SETTINGS (first request on a fresh connection) is
    // not handled here.
    if (data[3] != k_h2_frame_headers) {
        return false;
    }

    const u32 payload_len = ((u32)data[0] << 16) | ((u32)data[1] << 8) | (u32)data[2];

    // The frame (header + payload) must fit in what we pulled and hold at least a
    // traceparent entry.
    if (payload_len < k_h2_tp_hpack_size ||
        payload_len > k_h2_ingress_pull - k_h2_frame_header_len) {
        return false;
    }

    const u32 frame_end = k_h2_frame_header_len + payload_len;

    if ((void *)(data + frame_end) > (void *)end) {
        return false;
    }

    return validate_h2_tp_plain(data + (frame_end - k_h2_tp_hpack_size), end, out) != 0;
}
