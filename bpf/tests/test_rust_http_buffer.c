// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <bpfcore/bpf_helpers.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}
static inline long
bpf_loop(unsigned int n, int (*f)(unsigned int, void *), void *ctx, unsigned long long flags) {
    (void)flags;
    for (unsigned int i = 0; i < n; i++) {
        if (f(i, ctx)) {
            break;
        }
    }
    return 0;
}
static unsigned int writes, fail_at;
static bool fail_reads;
static long read_user(void *dst, unsigned int n, const void *src) {
    if (fail_reads) {
        return -EFAULT;
    }
    memcpy(dst, src, n);
    return 0;
}
static long write_user(void *dst, const void *src, unsigned int n) {
    if (++writes == fail_at) {
        return -EFAULT;
    }
    memcpy(dst, src, n);
    return 0;
}
#define bpf_probe_read_user read_user
#define bpf_probe_write_user write_user
#include <common/rust_http_buffer.h>

static unsigned char header_chunk[k_http1_read_chunk_bytes];
static unsigned char legacy_header[TRACE_BUF_SIZE];
static http1_header_scan_t header_scan;
static void *lookup_scratch(void *map, const void *key) {
    (void)key;
    if (map == &rust_http1_scan_storage) {
        return &header_scan;
    }
    if (map == &tp_char_buf_storage) {
        return legacy_header;
    }
    return map == &http1_header_buf_storage ? header_chunk : NULL;
}

typedef struct buffer {
    unsigned char *ptr;
    u64 len;
    u64 cap;
} buffer_t;
typedef struct limit {
    buffer_t *buffer;
    u64 remaining;
} limit_t;

static const rust_protocol_config_t config = {
    .bytes_ptr = offsetof(buffer_t, ptr),
    .bytes_len = offsetof(buffer_t, len),
    .bytes_cap = offsetof(buffer_t, cap),
    .limit_remaining = offsetof(limit_t, remaining),
};

static void test_forwarded_http1(bool use_bpf_loop) {
    const char original[] =
        "X-Test: keep\r\nTraceparent: 00-00000000000000000000000000000001-1111111111111111-01\r\n";
    const char expected[] =
        "X-Test: keep\r\nTraceparent: 00-00000000000000000000000000000001-0200000000000000-00\r\n";
    const tp_info_t wire = {
        .trace_id = {[TRACE_ID_SIZE_BYTES - 1] = 1}, .span_id = {2}, .flags = 0};
    g_bpf_traceparent_enabled = true;
    g_bpf_loop_enabled = use_bpf_loop;
    for (unsigned int fail = 0; fail <= 1; fail++) {
        unsigned char data[sizeof(original)];
        memcpy(data, original, sizeof(data));
        writes = 0;
        fail_at = fail;
        assert(rust_http1_rewrite_traceparent(
                   (u64)data, sizeof(data) - 1, &wire, g_bpf_loop_enabled) == !fail);
        assert(writes == 1);
        assert(memcmp(data, fail ? original : expected, sizeof(data)) == 0);
    }
    unsigned char missing[] = "X-Test: keep\r\n";
    writes = 0;
    fail_at = 0;
    assert(!rust_http1_rewrite_traceparent(
        (u64)missing, sizeof(missing) - 1, &wire, g_bpf_loop_enabled));
    assert(writes == 0);
    unsigned char embedded[] =
        "X-Test: traceparent: 00-00000000000000000000000000000001-1111111111111111-01\r\n";
    assert(!rust_http1_rewrite_traceparent(
        (u64)embedded, sizeof(embedded) - 1, &wire, g_bpf_loop_enabled));
    assert(writes == 0);
    g_bpf_traceparent_enabled = false;
}

static void test_large_forwarded_http1(void) {
    const unsigned char header[] =
        "Traceparent: 00-00000000000000000000000000000001-1111111111111111-01\r\n\r\n";
    const u32 offsets[] = {349,
                           350,
                           1000,
                           1020,
                           4090,
                           8190,
                           k_http1_max_header_bytes - TRACE_PARENT_HEADER_LEN,
                           k_http1_max_header_bytes - TRACE_PARENT_HEADER_LEN + 1};
    const tp_info_t wire = {.trace_id = {1}, .span_id = {2}, .flags = 0};
    g_bpf_traceparent_enabled = true;
    g_bpf_loop_enabled = true;
    fail_at = 0;
    for (u32 i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        unsigned char data[k_http1_max_header_bytes + sizeof(header)];
        const u32 offset = offsets[i];
        memset(data, 'a', offset);
        memcpy(data, "X-Padding: ", sizeof("X-Padding: ") - 1);
        memcpy(data + offset - 2, "\r\n", 2);
        memcpy(data + offset, header, sizeof(header));
        const u32 len = offset + sizeof(header) - 1;
        unsigned char expected[sizeof(data)];
        memcpy(expected, data, len);
        const bool fits = offset + TRACE_PARENT_HEADER_LEN <= k_http1_max_header_bytes;
        if (fits) {
            make_tp_string(expected + offset + TP_LOWER_SIZE, &wire);
        }
        writes = 0;
        assert(rust_http1_rewrite_traceparent((u64)data, len, &wire, g_bpf_loop_enabled) == fits);
        assert(writes == fits);
        assert(memcmp(data, expected, len) == 0);
        fail_reads = true;
        writes = 0;
        assert(!rust_http1_rewrite_traceparent((u64)data, len, &wire, g_bpf_loop_enabled));
        assert(writes == 0);
        fail_reads = false;
        memcpy(data + offset, header, sizeof(header));
        memcpy(expected, data, len);
        const bool legacy_fits = offset < 350;
        if (legacy_fits) {
            make_tp_string(expected + offset + TP_LOWER_SIZE, &wire);
        }
        g_bpf_loop_enabled = false;
        assert(rust_http1_rewrite_traceparent((u64)data, len, &wire, g_bpf_loop_enabled) ==
               legacy_fits);
        assert(writes == legacy_fits);
        assert(memcmp(data, expected, len) == 0);
        g_bpf_loop_enabled = true;
    }
    g_bpf_traceparent_enabled = false;
}

static void test_append(unsigned int fail) {
    unsigned char data[256] = {
        0, 0, 1, k_h2_frame_headers, k_h2_flag_end_headers, 0, 0, 0, 3, 0x82};
    buffer_t buffer = {.ptr = data, .len = 10, .cap = sizeof(data)};
    limit_t limit = {.buffer = &buffer, .remaining = 200};
    rust_http_args_t args = {.buffer = (u64)&buffer,
                             .limit = (u64)&limit,
                             .stream_id = 3,
                             .request.inject = 1,
                             .request.wire = {.trace_id = {1}, .span_id = {2}, .flags = 1}};
    writes = 0;
    fail_at = fail;
    bool result = rust_http2_append(&args, &config);
    assert(result == (fail == 0));
    assert(args.request.inject == (fail != 0));
    if (fail) {
        assert(buffer.len == 10 && limit.remaining == 200 && data[2] == 1);
    } else {
        assert(buffer.len == 10 + k_h2_tp_hpack_size);
        assert(limit.remaining == 200 - k_h2_tp_hpack_size);
        assert(data[2] == 1 + k_h2_tp_hpack_size && data[9] == 0x82);
        assert(data[10] == 0 && data[11] == 11);
        assert(memcmp(data + 12, "traceparent", 11) == 0);
        assert(memcmp(data + 24, "00-01000000000000000000000000000000-0200000000000000-01", 55) ==
               0);
    }
    // A full buffer, CONTINUATION frame, wrong stream, or oversized frame cannot be edited.
    buffer.len = 10;
    limit.remaining = 200;
    data[2] = 1;
    fail_at = 0;
    buffer.cap = 10;
    writes = 0;
    assert(!rust_http2_append(&args, &config) && writes == 0);
    buffer.cap = sizeof(data);
    data[3] = k_h2_frame_continuation;
    assert(!rust_http2_append(&args, &config) && writes == 0);
    data[3] = k_h2_frame_headers;
    args.stream_id = 5;
    assert(!rust_http2_append(&args, &config) && writes == 0);
    args.stream_id = 3;
    data[0] = 1;
    assert(!rust_http2_append(&args, &config) && writes == 0);
}

static void test_frame_fallback(void) {
    unsigned char hpack_data[] = {0x82};
    buffer_t hpack = {.ptr = hpack_data, .len = sizeof(hpack_data), .cap = sizeof(hpack_data)};
    unsigned char data[256] = {
        0, 0, 1, k_h2_frame_headers, k_h2_flag_end_headers, 0, 0, 0, 3, 0x82};
    buffer_t buffer = {.ptr = data, .len = 10, .cap = sizeof(data)};
    limit_t limit = {.buffer = &buffer, .remaining = 200};
    rust_http_args_t args = {.buffer = (u64)&buffer,
                             .hpack_buffer = (u64)&hpack,
                             .limit = (u64)&limit,
                             .stream_id = 3,
                             .request.inject = 1,
                             .request.wire = {.trace_id = {1}, .span_id = {2}, .flags = 1}};
    writes = 0;
    fail_at = 0;
    assert(!rust_hpack_append(&args, &config));
    assert(writes == 0 && args.request.inject);
    assert(rust_http2_append(&args, &config));
    assert(!args.request.inject && "trailers on this stream must not inject traceparent again");
}

int main(void) {
    bpf_map_lookup_elem_hook = lookup_scratch;
    test_forwarded_http1(false);
    test_forwarded_http1(true);
    test_large_forwarded_http1();
    test_frame_fallback();
    for (unsigned int fail = 0; fail <= 4; fail++) {
        test_append(fail);
    }
    for (unsigned int fail = 0; fail <= 2; fail++) {
        unsigned char data[128] = {0x82, 0x86, 0x84};
        buffer_t buffer = {.ptr = data, .len = 3, .cap = sizeof(data)};
        rust_http_args_t args = {.hpack_buffer = (u64)&buffer};
        writes = 0;
        fail_at = fail;
        assert(rust_hpack_append(&args, &config) == (fail == 0));
        assert(buffer.len == (fail ? 3 : 3 + k_h2_tp_hpack_size));
        assert(data[0] == 0x82 && data[1] == 0x86 && data[2] == 0x84);
        if (!fail) {
            assert(memcmp(data + 5, "traceparent", 11) == 0);
        }
        buffer.cap = buffer.len;
        writes = 0;
        assert(!rust_hpack_append(&args, &config) && writes == 0);
    }
    puts("Rust HTTP/2 buffer bounds and commit rollback checks passed");
    return 0;
}
