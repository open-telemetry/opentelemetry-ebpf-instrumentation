// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>
#include <common/scratch_mem.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline long bpf_loop(unsigned int count,
                            int (*callback)(unsigned int, void *),
                            void *ctx,
                            unsigned long long flags) {
    (void)flags;
    for (unsigned int i = 0; i < count; i++) {
        if (callback(i, ctx)) {
            break;
        }
    }
    return 0;
}

static unsigned int reads;
static unsigned int largest_read;
static bool fail_reads;

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    reads++;
    largest_read = size > largest_read ? size : largest_read;
    if (fail_reads) {
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

// The shared stubs no-op every read and map lookup: the scan needs real ones.
#define bpf_probe_read test_probe_read
#undef SCRATCH_MEM_SIZED
#define SCRATCH_MEM_SIZED(NAME, SIZE)                                                              \
    static unsigned char NAME##_storage[SIZE];                                                     \
    static __always_inline void *NAME##_mem(void) {                                                \
        return NAME##_storage;                                                                     \
    }
#include <common/http1_traceparent.h>
#undef bpf_probe_read

static const unsigned char header[] =
    "Traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";

static unsigned char request[k_http1_max_header_bytes + sizeof(header) + 128];

static u32 request_with_traceparent(u32 offset) {
    const char prefix[] = "GET / HTTP/1.1\r\nX-Padding: ";
    assert(offset >= sizeof(prefix) + 1);
    memcpy(request, prefix, sizeof(prefix) - 1);
    memset(request + sizeof(prefix) - 1, 'a', offset - sizeof(prefix) - 1);
    memcpy(request + offset - 2, "\r\n", 2);
    memcpy(request + offset, header, sizeof(header) - 1);
    memcpy(request + offset + sizeof(header) - 1, "\r\n", 2);
    return offset + sizeof(header) + 1;
}

static void scan(http1_header_scan_t *state, const unsigned char *buf, u32 len) {
    http1_read_headers(state, buf, len, k_http1_memory_any);
}

static void test_every_split(void) {
    const u32 len = request_with_traceparent(100);
    for (u32 split = 0; split <= len; split++) {
        http1_header_scan_t state = {};
        scan(&state, request, split);
        scan(&state, request + split, len - split);
        assert(state.present && state.valid && state.value_length == k_hpack_value_len_tp);
        const u32 value_offset = sizeof("traceparent: ") - 1;
        assert(memcmp(state.header + value_offset, header + value_offset, k_hpack_value_len_tp) ==
               0);
    }
}

static void test_large_fragmented_headers(void) {
    const u32 offsets[] = {
        1000, 1020, 4090, 8190, k_http1_max_header_bytes - TRACE_PARENT_HEADER_LEN};
    for (u32 i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        const u32 len = request_with_traceparent(offsets[i]);
        http1_header_scan_t state = {};
        for (u32 pos = 0; pos < len; pos++) {
            scan(&state, request + pos, 1);
        }
        assert(state.present && state.valid);
        assert(state.bytes == offsets[i] + TRACE_PARENT_HEADER_LEN);
    }
}

static void test_limit(void) {
    const u32 offsets[] = {k_http1_max_header_bytes - TRACE_PARENT_HEADER_LEN + 1,
                           k_http1_max_header_bytes};
    for (u32 i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        const u32 len = request_with_traceparent(offsets[i]);
        http1_header_scan_t state = {};
        scan(&state, request, 1000);
        scan(&state, request + 1000, len - 1000);
        assert(!state.valid);
        assert(state.phase == k_http1_headers_done);
        assert(state.bytes == k_http1_max_header_bytes);
    }
}

static void test_reads_only_the_chunks_it_scans(void) {
    const u32 offset = k_http1_read_chunk_bytes + 100;
    const u32 len = request_with_traceparent(offset);
    http1_header_scan_t state = {};
    reads = 0;
    largest_read = 0;
    scan(&state, request, k_http1_max_header_bytes);
    assert(state.present && state.valid);
    assert(len < k_http1_max_header_bytes);
    // the traceparent ends in the second chunk: the other 14 are never read
    assert(reads == 2);
    assert(largest_read == k_http1_read_chunk_bytes);
}

static void test_failed_read(void) {
    const u32 len = request_with_traceparent(100);
    http1_header_scan_t state = {};
    fail_reads = true;
    scan(&state, request, len);
    fail_reads = false;
    assert(!state.present && !state.valid);
    assert(state.phase == k_http1_headers_done);
}

static void test_headers_only(void) {
    const unsigned char input[] = "GET / HTTP/1.1\r\nX-Value: Traceparent: bogus\r\n\r\n";
    const u32 len = sizeof(input) - 1;
    for (u32 split = 0; split <= len; split++) {
        http1_header_scan_t state = {};
        scan(&state, input, split);
        scan(&state, input + split, len - split);
        scan(&state, header, sizeof(header) - 1);
        assert(!state.present && !state.valid);
        assert(state.bytes == len);
        assert(state.phase == k_http1_headers_done);
    }
}

static void test_malformed_header_is_preserved(void) {
    const unsigned char *values[] = {
        (const unsigned char *)"traceparent: invalid\r\n",
        (const unsigned char
             *)"traceparent: 00-00000000000000000000000000000000-0123456789abcdef-01\r\n",
        (const unsigned char
             *)"traceparent: 00-0123456789abcdef0123456789abcdef-0000000000000000-01\r\n",
        (const unsigned char
             *)"traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdeg-01\r\n",
        (const unsigned char
             *)"traceparent: ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n",
    };
    for (u32 i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        http1_header_scan_t state = {.phase = k_http1_header_name};
        scan(&state, values[i], strlen((const char *)values[i]));
        assert(state.present && !state.valid);
        assert(state.phase == k_http1_headers_done);
    }
}

static void test_header_name_and_spacing(void) {
    const unsigned char input[] =
        "tRaCePaReNt:\t00-0123456789abcdef0123456789abcdef-0123456789abcdef-00\r\n";
    http1_header_scan_t state = {.phase = k_http1_header_name};
    scan(&state, input, sizeof(input) - 1);
    assert(state.present && state.valid);
    assert(state.header[TRACE_PARENT_HEADER_LEN - 1] == '0');
}

int main(void) {
    test_every_split();
    test_large_fragmented_headers();
    test_limit();
    test_reads_only_the_chunks_it_scans();
    test_failed_read();
    test_headers_only();
    test_malformed_header_is_preserved();
    test_header_name_and_spacing();
    puts("HTTP/1 traceparent scan tests passed");
    return 0;
}
