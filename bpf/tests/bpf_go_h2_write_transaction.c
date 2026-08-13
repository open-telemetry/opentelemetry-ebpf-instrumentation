// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>
#include <common/scratch_mem.h>

static unsigned int write_calls;
static unsigned int failed_writes;

#define BPF_ANY 0

static u32 bpf_get_prandom_u32(void) {
    return 0;
}

static long bpf_loop(u32 iterations, int (*callback)(u32, void *), void *context, u64 flags) {
    (void)flags;
    for (u32 index = 0; index < iterations; index++) {
        if (callback(index, context)) {
            break;
        }
    }
    return 0;
}

static u64 bpf_ktime_get_ns(void) {
    return 0;
}

static long test_probe_read_user(void *dst, unsigned int size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}

static long test_probe_write_user(void *dst, const void *src, unsigned int size) {
    write_calls++;
    memcpy(dst, src, size);
    return (failed_writes & (1U << write_calls)) ? -1 : 0;
}

#define bpf_probe_read_user test_probe_read_user
#define bpf_probe_write_user test_probe_write_user
#define bpf_memset memset
#undef SCRATCH_MEM_SIZED
#define SCRATCH_MEM_SIZED(NAME, SIZE)                                                              \
    static unsigned char NAME##_storage[SIZE];                                                     \
    static __always_inline void *NAME##_mem(void) {                                                \
        return NAME##_storage;                                                                     \
    }
#include <gotracer/go_h2_write.h>
#undef bpf_probe_read_user
#undef bpf_probe_write_user
#undef bpf_memset

struct writer {
    s64 n;
};

static unsigned char
    large_frame[k_h2_default_max_frame_size + k_h2_frame_header_len + k_h2_tp_continuation_size];

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void reset_frame(unsigned char *frame, struct writer *writer) {
    memset(frame, 0, 512);
    frame[2] = 1;
    frame[3] = k_h2_frame_headers;
    frame[4] = k_h2_flag_end_headers;
    frame[8] = 1;
    frame[9] = 0x82;
    writer->n = 10;
    write_calls = 0;
    failed_writes = 0;
}

static u8 append(unsigned char *frame, struct writer *writer, const tp_info_t *tp) {
    return append_go_h2_traceparent(
        writer, 0, frame, 0, writer->n, 512, 1, k_h2_frame_headers, tp, true);
}

static void test_preflush_rollback(const tp_info_t *tp) {
    unsigned char frame[512];
    struct writer writer;
    reset_frame(frame, &writer);
    frame[0] = 0;
    frame[1] = 0;
    frame[2] = 0;
    failed_writes = 1U << 2;
    expect(append_go_h2_traceparent_preflush(
               &writer, 0, frame, writer.n, 512, 1, k_h2_frame_headers, tp) ==
               k_go_h2_user_write_pristine,
           "preflush length failure rolls back");
    expect(writer.n == 10, "preflush rollback restores writer length");

    reset_frame(frame, &writer);
    frame[0] = 0;
    frame[1] = 0;
    frame[2] = 0;
    failed_writes = (1U << 2) | (1U << 3);
    expect(append_go_h2_traceparent_preflush(
               &writer, 0, frame, writer.n, 512, 1, k_h2_frame_headers, tp) ==
               k_go_h2_user_write_uncertain,
           "unverified preflush rollback is uncertain");
}

static void test_continuation_rollback(const tp_info_t *tp) {
    struct writer writer = {.n = k_h2_frame_header_len + k_h2_default_max_frame_size};
    memset(large_frame, 0, sizeof(large_frame));
    large_frame[0] = 0;
    large_frame[1] = 0x40;
    large_frame[2] = 0;
    large_frame[3] = k_h2_frame_headers;
    large_frame[4] = k_h2_flag_end_headers;
    large_frame[8] = 1;

    write_calls = 0;
    failed_writes = 1U << 2;
    expect(append_go_h2_traceparent(&writer,
                                    0,
                                    large_frame,
                                    0,
                                    writer.n,
                                    sizeof(large_frame),
                                    1,
                                    k_h2_frame_headers,
                                    tp,
                                    true) == k_go_h2_user_write_pristine,
           "continuation flag failure rolls back");
    expect(writer.n == k_h2_frame_header_len + k_h2_default_max_frame_size &&
               large_frame[4] == k_h2_flag_end_headers,
           "continuation rollback restores length and END_HEADERS");

    writer.n = k_h2_frame_header_len + k_h2_default_max_frame_size;
    large_frame[4] = k_h2_flag_end_headers;
    write_calls = 0;
    failed_writes = 1U << 3;
    expect(append_go_h2_traceparent(&writer,
                                    0,
                                    large_frame,
                                    0,
                                    writer.n,
                                    sizeof(large_frame),
                                    1,
                                    k_h2_frame_headers,
                                    tp,
                                    true) == k_go_h2_user_write_pristine,
           "continuation writer-length failure rolls back");
    expect(writer.n == k_h2_frame_header_len + k_h2_default_max_frame_size &&
               large_frame[4] == k_h2_flag_end_headers,
           "continuation writer-length rollback restores metadata");

    writer.n = k_h2_frame_header_len + k_h2_default_max_frame_size;
    large_frame[4] = k_h2_flag_end_headers;
    write_calls = 0;
    failed_writes = (1U << 3) | (1U << 4);
    expect(append_go_h2_traceparent(&writer,
                                    0,
                                    large_frame,
                                    0,
                                    writer.n,
                                    sizeof(large_frame),
                                    1,
                                    k_h2_frame_headers,
                                    tp,
                                    true) == k_go_h2_user_write_uncertain,
           "unverified continuation rollback is uncertain");
}

static void test_reserved_padding_failure(const tp_info_t *tp) {
    unsigned char frame[128] = {};
    const s64 n = k_h2_frame_header_len + 1 + k_h2_tp_hpack_size;
    frame[3] = k_h2_frame_headers;
    frame[4] = k_h2_flag_end_headers | k_h2_flag_padded;
    frame[8] = 1;
    frame[9] = k_h2_tp_hpack_size;

    write_calls = 0;
    failed_writes = 1U << 1;
    expect(commit_go_h2_reserved_padding(frame, n, 1, tp) == k_go_h2_user_write_pristine,
           "failed field write leaves padding authoritative");
    expect(frame[9] == k_h2_tp_hpack_size, "field failure preserves padding length");

    memset(frame + 10, 0, k_h2_tp_hpack_size);
    write_calls = 0;
    failed_writes = 1U << 2;
    expect(commit_go_h2_reserved_padding(frame, n, 1, tp) == k_go_h2_user_write_uncertain,
           "unverified padding consumption is uncertain");
}

int main(void) {
    unsigned char frame[512];
    struct writer writer;
    tp_info_t tp = {};

    reset_frame(frame, &writer);
    expect(append(frame, &writer, &tp) == k_go_h2_user_write_committed,
           "complete transaction commits");
    expect(writer.n == 10 + k_h2_tp_hpack_size, "commit advances writer length");
    expect(frame[2] == 1 + k_h2_tp_hpack_size, "commit advances frame length");
    expect(go_h2_state_after_user_write(k_go_h2_state_obi_pending, k_go_h2_user_write_committed) ==
               k_go_h2_state_obi_written,
           "commit alone advances pending to written");

    reset_frame(frame, &writer);
    failed_writes = 1U << 2;
    expect(append(frame, &writer, &tp) == k_go_h2_user_write_pristine,
           "frame-length failure rolls back");
    expect(writer.n == 10 && frame[2] == 1, "frame-length rollback restores metadata");
    expect(go_h2_state_after_user_write(k_go_h2_state_obi_pending, k_go_h2_user_write_pristine) ==
               k_go_h2_state_obi_pending,
           "verified rollback remains pending for socket fallback");

    reset_frame(frame, &writer);
    failed_writes = 1U << 3;
    expect(append(frame, &writer, &tp) == k_go_h2_user_write_pristine,
           "writer-length failure rolls back");
    expect(writer.n == 10 && frame[2] == 1, "writer-length rollback restores both fields");

    reset_frame(frame, &writer);
    failed_writes = (1U << 2) | (1U << 3);
    expect(append(frame, &writer, &tp) == k_go_h2_user_write_uncertain,
           "unverified rollback is uncertain");
    expect(go_h2_state_after_user_write(k_go_h2_state_obi_pending, k_go_h2_user_write_uncertain) ==
               k_go_h2_state_skip,
           "uncertain rollback fails closed");

    expect(go_h2_state_after_user_write(k_go_h2_state_app, k_go_h2_user_write_committed) ==
               k_go_h2_state_app,
           "a write result cannot replace application ownership");

    test_preflush_rollback(&tp);
    test_continuation_rollback(&tp);
    test_reserved_padding_failure(&tp);

    printf("OK: %s\n", __FILE__);
    return 0;
}
