// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// fill_msg_buffers() copies the head of an outgoing message into msg_buffer_mem
// and records how much it copied in msg_buffer_t.real_size. The kprobe on
// tcp_sendmsg reads real_size back and hands that many bytes of msg_buffer_mem
// to the protocol parsers, so real_size must never describe more than was
// written. msg_buffer_mem is a BPF_MAP_TYPE_PERCPU_ARRAY that nothing clears
// between messages, so every byte inside real_size this call did not write is
// the previous message on this CPU.
//
// The length that has to hold is the one at the buffer's own size. A message of
// exactly k_msg_buffer_size_max bytes is the largest one that fits, and it is
// also the one a power-of-two mask maps onto zero.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static long test_probe_read_kernel(void *dst, unsigned int size, const void *src);

#define bpf_probe_read_kernel test_probe_read_kernel

#include <common/msg_buffer.h>

#undef bpf_probe_read_kernel

enum {
    // Larger than the buffer, so a message can be longer than what is copied.
    k_src_len = k_msg_buffer_size_max * 2,
    // A byte no source position holds, left in the destination beforehand. Any
    // occurrence below the reported length is a byte this call never wrote.
    // build_src() cycles 0..250, so anything above that can never collide with
    // the source pattern at any offset.
    k_residue = 0xFF,
};

static unsigned char src[k_src_len];
static unsigned char dst[k_msg_buffer_size_max];

static int reads_fail;

static long test_probe_read_kernel(void *d, unsigned int size, const void *s) {
    if (reads_fail) {
        // A faulting bpf_probe_read_kernel() copies nothing at all.
        return -1;
    }

    memcpy(d, s, size);
    return 0;
}

static void fail(const char *message, unsigned long expected, unsigned long actual) {
    fprintf(stderr, "FAIL: %s\n  expected %lu, got %lu\n", message, expected, actual);
    exit(1);
}

static void assert_eq(unsigned long expected, unsigned long actual, const char *message) {
    if (expected != actual) {
        fail(message, expected, actual);
    }
}

// Fills src with a pattern that never contains k_residue, so the destination
// can be checked byte for byte.
static void build_src(void) {
    for (int i = 0; i < k_src_len; i++) {
        src[i] = (unsigned char)(i % 251);
    }
}

static void fill_with_residue(void) {
    memset(dst, k_residue, sizeof(dst));
}

// Reports how many leading bytes of dst hold the head of src.
static unsigned long copied_prefix(void) {
    unsigned long n = 0;

    while (n < sizeof(dst) && dst[n] == src[n]) {
        n++;
    }

    return n;
}

// Reports the first position at or after `from` that is not the residue.
static unsigned long first_written_at_or_after(unsigned long from) {
    unsigned long n = from;

    while (n < sizeof(dst) && dst[n] == k_residue) {
        n++;
    }

    return n;
}

static void check_copy(u32 msg_size, u16 want, const char *message) {
    fill_with_residue();

    const u16 copied = msg_buffer_copy(dst, src, msg_size);

    assert_eq(want, copied, message);
    assert_eq(want, copied_prefix(), "the bytes copied are exactly the reported length");
    assert_eq(sizeof(dst),
              first_written_at_or_after(want),
              "nothing past the reported length was written");
}

// A message of exactly k_msg_buffer_size_max bytes is the largest one that
// fits. Masking a length with k_msg_buffer_size_max - 1 turns it into a copy of
// zero bytes while still reporting the full length.
static void test_message_at_the_buffer_size_is_copied_whole(void) {
    check_copy(k_msg_buffer_size_max,
               k_msg_buffer_size_max,
               "a message the size of the buffer copies the whole buffer");
}

static void test_message_larger_than_the_buffer_fills_it(void) {
    check_copy(k_src_len, k_msg_buffer_size_max, "a message larger than the buffer fills it");

    // Every length above the buffer's size lands on the same truncation, and a
    // mask sends a whole class of them to zero rather than only the boundary.
    check_copy(k_msg_buffer_size_max + 1, k_msg_buffer_size_max, "one byte over the buffer");
    check_copy(k_msg_buffer_size_max * 2 - 1, k_msg_buffer_size_max, "just under twice over");
}

static void test_message_below_the_buffer_size_is_copied_whole(void) {
    check_copy(k_msg_buffer_size_max - 1, k_msg_buffer_size_max - 1, "one byte under the buffer");
    check_copy(4096, 4096, "a mid-sized message");
    check_copy(1, 1, "a one byte message");
}

// The buffer is only ever read up to the reported length, so copying more than
// the message holds reads past the extent the caller made readable.
static void test_short_message_copies_only_its_own_bytes(void) {
    check_copy(100, 100, "a message shorter than k_kprobes_http2_buf_size");
    check_copy(k_kprobes_http2_buf_size - 1, k_kprobes_http2_buf_size - 1, "one byte under it");
}

static void test_empty_message_reports_nothing(void) {
    fill_with_residue();

    assert_eq(0, msg_buffer_copy(dst, src, 0), "an empty message reports no bytes");
    assert_eq(sizeof(dst), first_written_at_or_after(0), "and writes nothing");
}

// bpf_probe_read_kernel() is all-or-nothing. A length that survived the failure
// would name bytes belonging to the previous message on this CPU.
static void test_failed_read_reports_nothing(void) {
    reads_fail = 1;
    fill_with_residue();

    const u16 copied = msg_buffer_copy(dst, src, k_msg_buffer_size_max);

    reads_fail = 0;

    assert_eq(0, copied, "a faulting read reports no bytes");
    assert_eq(sizeof(dst), first_written_at_or_after(0), "and leaves the residue in place");
}

// real_size is a u16, so the reported length has to fit in one.
static void test_reported_length_fits_the_field(void) {
    msg_buffer_t msg_buf = {0};

    msg_buf.real_size = msg_buffer_copy(dst, src, k_src_len);

    assert_eq(k_msg_buffer_size_max, msg_buf.real_size, "real_size holds the full buffer length");
}

int main(void) {
    build_src();

    test_message_at_the_buffer_size_is_copied_whole();
    test_message_larger_than_the_buffer_fills_it();
    test_message_below_the_buffer_size_is_copied_whole();
    test_short_message_copies_only_its_own_bytes();
    test_empty_message_reports_nothing();
    test_failed_read_reports_nothing();
    test_reported_length_fits_the_field();

    printf("bpf_msg_buffer_copy: all tests passed\n");
    return 0;
}
