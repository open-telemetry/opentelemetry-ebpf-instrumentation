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
static unsigned int partial_writes;

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

static long test_probe_read_user(void *dst, unsigned int size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}

static long test_probe_write_user(void *dst, const void *src, unsigned int size) {
    write_calls++;
    if (partial_writes & (1U << write_calls)) {
        memcpy(dst, src, size / 2);
        return -1;
    }
    if (failed_writes & (1U << write_calls)) {
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

#define bpf_probe_read_user test_probe_read_user
#define bpf_probe_write_user test_probe_write_user
#undef SCRATCH_MEM_SIZED
#define SCRATCH_MEM_SIZED(NAME, SIZE)                                                              \
    static unsigned char NAME##_storage[SIZE];                                                     \
    static __always_inline void *NAME##_mem(void) {                                                \
        return NAME##_storage;                                                                     \
    }
#include <gotracer/go_h2_write.h>
#undef bpf_probe_read_user
#undef bpf_probe_write_user

struct writer {
    s64 n;
};

enum { k_original_n = k_h2_frame_header_len + 1, k_buffer_size = 256 };

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void reset_frame(unsigned char frame[k_buffer_size], struct writer *writer) {
    memset(frame, 0, k_buffer_size);
    frame[2] = 1;
    frame[3] = k_h2_frame_headers;
    frame[4] = k_h2_flag_end_headers;
    frame[8] = 1;
    frame[9] = 0x82;
    writer->n = k_original_n;
    write_calls = 0;
    failed_writes = 0;
    partial_writes = 0;
}

static u8 append(unsigned char frame[k_buffer_size], struct writer *writer, const tp_info_t *tp) {
    return append_go_h2_traceparent(writer, 0, frame, 0, writer->n, k_buffer_size, 1, tp);
}

static void expect_pristine(const unsigned char frame[k_buffer_size],
                            const struct writer *writer,
                            const char *message) {
    expect(writer->n == k_original_n && frame[0] == 0 && frame[1] == 0 && frame[2] == 1, message);
}

static void expect_committed(const unsigned char frame[k_buffer_size],
                             const struct writer *writer,
                             const char *message) {
    expect(writer->n == k_original_n + k_h2_tp_hpack_huffman_size && frame[0] == 0 &&
               frame[1] == 0 && frame[2] == 1 + k_h2_tp_hpack_huffman_size &&
               frame[k_original_n] == k_hpack_literal_no_index &&
               frame[k_original_n + 1] == (k_hpack_huffman_flag | k_hpack_tp_name_huffman_len),
           message);
}

static void test_success(const tp_info_t *tp) {
    unsigned char frame[k_buffer_size];
    struct writer writer;
    reset_frame(frame, &writer);

    expect(append(frame, &writer, tp) == k_go_h2_user_write_committed,
           "complete transaction reports committed");
    expect_committed(frame, &writer, "complete transaction publishes one complete field");
}

static void test_forward_write_failures(const tp_info_t *tp) {
    unsigned char frame[k_buffer_size];
    struct writer writer;

    reset_frame(frame, &writer);
    failed_writes = 1U << 1;
    expect(append(frame, &writer, tp) == k_go_h2_user_write_pristine,
           "field write failure reports pristine");
    expect_pristine(frame, &writer, "field write failure leaves original metadata");

    reset_frame(frame, &writer);
    partial_writes = 1U << 1;
    expect(append(frame, &writer, tp) == k_go_h2_user_write_pristine,
           "partial field write reports pristine");
    expect_pristine(frame, &writer, "partial field write remains unpublished");

    reset_frame(frame, &writer);
    failed_writes = 1U << 2;
    expect(append(frame, &writer, tp) == k_go_h2_user_write_pristine,
           "frame length failure reports pristine");
    expect_pristine(frame, &writer, "frame length failure leaves the original frame sendable");

    reset_frame(frame, &writer);
    partial_writes = 1U << 2;
    expect(append(frame, &writer, tp) == k_go_h2_user_write_pristine,
           "partial frame length write rolls back");
    expect_pristine(frame, &writer, "partial frame length rollback restores all metadata");

    reset_frame(frame, &writer);
    failed_writes = 1U << 3;
    expect(append(frame, &writer, tp) == k_go_h2_user_write_pristine,
           "writer length failure rolls back");
    expect_pristine(frame, &writer, "writer length rollback restores the original frame");

    reset_frame(frame, &writer);
    partial_writes = 1U << 3;
    expect(append(frame, &writer, tp) == k_go_h2_user_write_committed,
           "writer write error accepts a fully published value");
    expect_committed(frame, &writer, "readback recognizes a complete writer publication");
}

static void test_recovery_write_failures(const tp_info_t *tp) {
    unsigned char frame[k_buffer_size];
    struct writer writer;

    reset_frame(frame, &writer);
    failed_writes = (1U << 3) | (1U << 4);
    expect(append(frame, &writer, tp) == k_go_h2_user_write_pristine,
           "failed writer rollback still verifies pristine state");
    expect_pristine(frame, &writer, "frame rollback alone restores the original frame");

    reset_frame(frame, &writer);
    failed_writes = (1U << 3) | (1U << 5);
    expect(append(frame, &writer, tp) == k_go_h2_user_write_committed,
           "failed frame rollback finishes the commit");
    expect_committed(frame, &writer, "commit recovery publishes consistent metadata");

    reset_frame(frame, &writer);
    failed_writes = (1U << 3) | (1U << 4) | (1U << 5) | (1U << 6);
    expect(append(frame, &writer, tp) == k_go_h2_user_write_committed,
           "failed finish-frame retry accepts an already published frame length");
    expect_committed(frame, &writer, "writer publication completes the transaction");

    reset_frame(frame, &writer);
    failed_writes = (1U << 3) | (1U << 4) | (1U << 5) | (1U << 7);
    expect(append(frame, &writer, tp) == k_go_h2_user_write_uncertain,
           "unrecoverable writer publication fails closed");
}

static void test_preflight(const tp_info_t *tp) {
    unsigned char frame[k_buffer_size];
    struct writer writer;

    reset_frame(frame, &writer);
    expect(append_go_h2_traceparent(&writer, 0, frame, -1, writer.n, k_buffer_size, 1, tp) ==
               k_go_h2_user_write_bypass,
           "invalid frame offset bypasses before mutation");
    expect(write_calls == 0, "offset preflight performs no writes");

    reset_frame(frame, &writer);
    expect(append_go_h2_traceparent(&writer, 0, frame, 0, writer.n + 1, k_buffer_size, 1, tp) ==
               k_go_h2_user_write_bypass,
           "writer and frame length mismatch bypasses before mutation");
    expect(write_calls == 0, "length-state preflight performs no writes");

    reset_frame(frame, &writer);
    frame[3] = k_h2_frame_data;
    expect(append(frame, &writer, tp) == k_go_h2_user_write_bypass,
           "non-HEADERS frame bypasses before mutation");
    expect(write_calls == 0, "frame-type preflight performs no writes");

    reset_frame(frame, &writer);
    expect(append_go_h2_traceparent(&writer, 0, frame, 0, writer.n, writer.n, 1, tp) ==
               k_go_h2_user_write_bypass,
           "insufficient capacity bypasses before mutation");
    expect(write_calls == 0, "capacity preflight performs no writes");

    reset_frame(frame, &writer);
    frame[4] = 0;
    expect(append(frame, &writer, tp) == k_go_h2_user_write_bypass,
           "CONTINUATION-dependent headers bypass direct injection");
    expect(write_calls == 0, "END_HEADERS preflight performs no writes");

    reset_frame(frame, &writer);
    expect(append_go_h2_traceparent(&writer, 0, frame, 0, writer.n, k_buffer_size, 3, tp) ==
               k_go_h2_user_write_bypass,
           "stream mismatch bypasses direct injection");
    expect(write_calls == 0, "stream preflight performs no writes");
}

int main(void) {
    tp_info_t tp = {.flags = 1};
    memset(tp.trace_id, 0x11, sizeof(tp.trace_id));
    memset(tp.span_id, 0x22, sizeof(tp.span_id));

    test_success(&tp);
    test_forward_write_failures(&tp);
    test_recovery_write_failures(&tp);
    test_preflight(&tp);

    printf("OK: %s\n", __FILE__);
    return 0;
}
