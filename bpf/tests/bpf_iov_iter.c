// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static long test_probe_read(void *dst, u32 size, const void *src) {
    if (!src) {
        memset(dst, 0, size);
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

#define bpf_probe_read test_probe_read
#define bpf_probe_read_kernel test_probe_read
#include <common/iov_iter.h>
#undef bpf_probe_read_kernel
#undef bpf_probe_read

static unsigned char buf[k_iovec_max_len * 2];

static void expect(bool condition, const char *description) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", description);
        exit(1);
    }
}

// netty hands each HTTP/2 frame header and payload over as its own buffer, so a few
// responses flushed together take more buffers than the reader used to walk
static void test_many_small_buffers(void) {
    enum { k_frames = 20, k_header_len = 9, k_payload_len = 5 };
    unsigned char frames[k_frames][k_header_len + k_payload_len];
    struct iovec iov[k_frames * 2];

    for (u32 f = 0; f < k_frames; f++) {
        for (u32 b = 0; b < sizeof(frames[f]); b++) {
            frames[f][b] = (unsigned char)(f * sizeof(frames[f]) + b);
        }
        iov[2 * f] = (struct iovec){.iov_base = frames[f], .iov_len = k_header_len};
        iov[2 * f + 1] =
            (struct iovec){.iov_base = frames[f] + k_header_len, .iov_len = k_payload_len};
    }

    iovec_iter_ctx ctx = {.iov = iov, .nr_segs = k_frames * 2};
    memset(buf, 0, sizeof(buf));
    expect(read_iovec_ctx(&ctx, buf, sizeof(frames)) == (int)sizeof(frames),
           "every small buffer is read");
    expect(memcmp(buf, frames, sizeof(frames)) == 0, "the buffers are read in order");
}

// a receive can fill only part of the last buffer
static void test_partial_last_buffer(void) {
    unsigned char first[50];
    unsigned char second[50];
    memset(first, 'a', sizeof(first));
    memset(second, 'b', sizeof(second));
    struct iovec iov[] = {
        {.iov_base = first, .iov_len = sizeof(first)},
        {.iov_base = second, .iov_len = sizeof(second)},
    };

    iovec_iter_ctx ctx = {.iov = iov, .nr_segs = 2};
    memset(buf, 0, sizeof(buf));
    expect(read_iovec_ctx(&ctx, buf, 80) == 80, "the read stops at the length received");
    expect(buf[49] == 'a' && buf[50] == 'b' && buf[79] == 'b' && buf[80] == 0,
           "the last buffer is read in part");
}

static void test_empty_buffers_skipped(void) {
    unsigned char data[] = "abcdef";
    struct iovec iov[] = {
        {.iov_base = data, .iov_len = 3},
        {.iov_base = data, .iov_len = 0},
        {.iov_base = NULL, .iov_len = 4},
        {.iov_base = data + 3, .iov_len = 3},
    };

    iovec_iter_ctx ctx = {.iov = iov, .nr_segs = 4};
    memset(buf, 0, sizeof(buf));
    expect(read_iovec_ctx(&ctx, buf, 6) == 6, "empty buffers add nothing");
    expect(memcmp(buf, data, 6) == 0, "empty buffers leave no gap");
}

int main(void) {
    test_many_small_buffers();
    test_partial_last_buffer();
    test_empty_buffers_skipped();

    puts("OK: bpf_iov_iter.c");
    return 0;
}
