// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/go_addr_key.h>
#include <common/common.h>
#include <common/http1_traceparent.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>
#include <gotracer/go_offsets.h>

enum : s64 { k_go_http1_no_refill = -1 };

typedef struct go_http1_header_scan {
    u64 reader;
    s64 refill_start; // buffer offset of the bytes the last fill read, or k_go_http1_no_refill
    http1_header_scan_t scan;
    u8 _pad[4];
} go_http1_header_scan_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, go_http1_header_scan_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_http1_header_scans SEC(".maps");

SCRATCH_MEM_TYPED(go_http1_header_scan, go_http1_header_scan_t);

static __always_inline void scan_go_http1_buffer(go_http1_header_scan_t *headers, s64 start) {
    if (headers->scan.phase == k_http1_headers_done) {
        return;
    }

    off_table_t *ot = get_offsets_table();
    const unsigned char *reader = (const unsigned char *)headers->reader;
    go_slice_t buffer = {};
    s64 end = 0;

    long err = bpf_probe_read_user(
        &buffer, sizeof(buffer), reader + go_offset_of(ot, (go_offset){.v = _buf_reader_buf_pos}));
    err |= bpf_probe_read_user(
        &end, sizeof(end), reader + go_offset_of(ot, (go_offset){.v = _buf_reader_w_pos}));

    if (err || !buffer.array || start < 0 || end < start || end > buffer.len) {
        headers->scan.valid = false;
        headers->scan.phase = k_http1_headers_done;

        return;
    }

    u64 len = end - start;
    bpf_clamp_umax(len, k_http1_max_header_bytes);
    http1_read_headers(
        &headers->scan, (const unsigned char *)buffer.array + start, len, k_http1_memory_user);
    bpf_d_printk(
        "read headers len=%d, valid=%d, found=%d", len, headers->scan.valid, headers->scan.present);
}

// The reader buffer keeps the bytes of the last fill until the next fill
// slides them away, so they can be scanned from the next fill or the
// readMIMEHeader return instead of a return probe on every fill.
static __always_inline void scan_go_http1_refill(go_http1_header_scan_t *headers) {
    if (headers->refill_start == k_go_http1_no_refill) {
        return;
    }
    scan_go_http1_buffer(headers, headers->refill_start);
    headers->refill_start = k_go_http1_no_refill;
}
