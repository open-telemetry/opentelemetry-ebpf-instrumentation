// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run me with: make && ./test_large_buffer_loop

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <common/algorithm.h>

#include <generictracer/protocol_common.h>

typedef struct {
    uint32_t total_tests;
    uint32_t passed_tests;
    uint32_t failed_tests;
} test_stats_t;

typedef struct {
    uint32_t num_chunks;
    uint32_t total_bytes_sent;
    enum large_buf_action final_action;
    uint32_t loop_iterations;
} loop_result_t;

static loop_result_t g_result;
static test_stats_t stats = {0, 0, 0};
static const char *g_test_name = NULL;

static void test_assert(bool condition, const char *msg) {
    stats.total_tests++;

    if (condition) {
        stats.passed_tests++;
        printf("✓ PASS: %s - %s\n", g_test_name, msg);
    } else {
        stats.failed_tests++;
        printf("✗ FAIL: %s - %s\n", g_test_name, msg);
    }
}

static long
ringbuf_count_hook(void *rb, void *data, unsigned long long sz, unsigned long long flags) {
    (void)rb;
    (void)sz;
    (void)flags;

    const tcp_large_buffer_t *buf = (const tcp_large_buffer_t *)data;

    g_result.num_chunks++;
    g_result.loop_iterations++;
    g_result.total_bytes_sent += buf->len;
    g_result.final_action = buf->action;

    return 0;
}

static loop_result_t run_emit_chunks(uint32_t available_bytes,
                                     enum large_buf_action initial_action) {
    static unsigned char fake_lb[sizeof(tcp_large_buffer_t) + k_large_buf_max_size];
    static unsigned char dummy_src[k_large_buf_max_http_captured_bytes];

    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)fake_lb;
    large_buf->action = initial_action;

    g_result = (loop_result_t){.final_action = initial_action};

    bpf_ringbuf_output_hook = ringbuf_count_hook;
    large_buf_emit_chunks(large_buf, dummy_src, available_bytes);
    bpf_ringbuf_output_hook = NULL;

    return g_result;
}

// Typical caller: clamps to the per-protocol max before calling large_buf_emit_chunks.
static loop_result_t simulate_with_protocol_max(uint32_t bytes_len,
                                                uint32_t max_captured,
                                                enum large_buf_action initial_action) {
    const uint32_t available = min(bytes_len, max_captured);
    return run_emit_chunks(available, initial_action);
}

// Test cases
static void test_empty_buffer() {
    const loop_result_t result = run_emit_chunks(0, k_large_buf_action_init);

    test_assert(result.num_chunks == 0, "should produce 0 chunks for empty buffer");
    test_assert(result.total_bytes_sent == 0, "should send 0 bytes");
    test_assert(result.final_action == k_large_buf_action_init, "should keep init action");
    test_assert(result.loop_iterations == 0, "should iterate 0 times");
}

static void test_small_buffer() {
    const uint32_t size = 1024;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_init);

    test_assert(result.num_chunks == 1, "should produce 1 chunk");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
    test_assert(result.final_action == k_large_buf_action_init, "should have init action");
    test_assert(result.loop_iterations == 1, "should iterate once");
}

static void test_exact_chunk_size() {
    const uint32_t size = k_large_buf_payload_max_size;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_init);

    test_assert(result.num_chunks == 1, "should produce 1 chunk");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
    test_assert(result.final_action == k_large_buf_action_init, "should have init action");
    test_assert(result.loop_iterations == 1, "should iterate once");
}

static void test_one_byte_over_chunk() {
    const uint32_t size = k_large_buf_payload_max_size + 1;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_init);

    test_assert(result.num_chunks == 2, "should produce 2 chunks");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
    test_assert(result.final_action == k_large_buf_action_append, "final action should be append");
    test_assert(result.loop_iterations == 2, "should iterate twice");
}

static void test_slightly_over_chunk() {
    const uint32_t size = 17000;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_init);

    test_assert(result.num_chunks == 2, "should produce 2 chunks");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
    test_assert(result.final_action == k_large_buf_action_append, "final action should be append");
}

static void test_exact_two_chunks() {
    const uint32_t size = 2 * k_large_buf_payload_max_size;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_init);

    test_assert(result.num_chunks == 2, "should produce 2 chunks");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
    test_assert(result.final_action == k_large_buf_action_append, "final action should be append");
}

static void test_three_chunks() {
    const uint32_t size = 3 * k_large_buf_payload_max_size;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_init);

    test_assert(result.num_chunks == 3, "should produce 3 chunks");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
    test_assert(result.final_action == k_large_buf_action_append, "final action should be append");
}

static void test_exact_max_captured() {
    const uint32_t size = k_large_buf_max_http_captured_bytes;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_init);

    test_assert(result.num_chunks == 4, "should produce 4 chunks");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
    test_assert(result.final_action == k_large_buf_action_append, "final action should be append");
}

static void test_over_max_captured() {
    const uint32_t size = k_large_buf_max_http_captured_bytes + 1000;

    const loop_result_t result = simulate_with_protocol_max(
        size, k_large_buf_max_http_captured_bytes, k_large_buf_action_init);

    test_assert(result.num_chunks == 4, "should produce 4 chunks (clamped by caller)");
    test_assert(result.total_bytes_sent == k_large_buf_max_http_captured_bytes,
                "should send only max_captured bytes");
    test_assert(result.final_action == k_large_buf_action_append, "final action should be append");
}

static void test_very_large_buffer() {
    const uint32_t size = 1024 * 1024;

    const loop_result_t result = simulate_with_protocol_max(
        size, k_large_buf_max_http_captured_bytes, k_large_buf_action_init);

    test_assert(result.num_chunks == 4, "should produce 4 chunks (clamped by caller)");
    test_assert(result.total_bytes_sent == k_large_buf_max_http_captured_bytes,
                "should send only max_captured bytes");
}

static void test_boundary_minus_one() {
    const uint32_t size = k_large_buf_payload_max_size - 1;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_init);

    test_assert(result.num_chunks == 1, "should produce 1 chunk");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
    test_assert(result.final_action == k_large_buf_action_init, "should have init action");
}

static void test_boundary_plus_one() {
    const uint32_t size = k_large_buf_payload_max_size + 1;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_init);

    test_assert(result.num_chunks == 2, "should produce 2 chunks");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
}

static void test_with_append_action() {
    const uint32_t size = 2 * k_large_buf_payload_max_size;

    const loop_result_t result = run_emit_chunks(size, k_large_buf_action_append);

    test_assert(result.num_chunks == 2, "should produce 2 chunks");
    test_assert(result.total_bytes_sent == size, "should send all bytes");
    test_assert(result.final_action == k_large_buf_action_append, "final action should be append");
}

static void test_chunk_distribution() {
    const uint32_t size = (3 * k_large_buf_payload_max_size) + 1000;
    uint32_t available_bytes = size;

    uint32_t chunk_sizes[10] = {0};
    uint32_t chunk_count = 0;

    const uint32_t niter = (available_bytes / k_large_buf_payload_max_size) +
                           ((available_bytes % k_large_buf_payload_max_size) > 0);

    for (uint32_t b = 0; b < niter; b++) {
        const uint32_t read_size = available_bytes > k_large_buf_payload_max_size
                                       ? k_large_buf_payload_max_size
                                       : available_bytes;
        chunk_sizes[chunk_count++] = read_size;
        available_bytes -= read_size;
    }

    test_assert(chunk_count == 4, "should have 4 chunks");
    test_assert(chunk_sizes[0] == k_large_buf_payload_max_size, "chunk 0 should be full size");
    test_assert(chunk_sizes[1] == k_large_buf_payload_max_size, "chunk 1 should be full size");
    test_assert(chunk_sizes[2] == k_large_buf_payload_max_size, "chunk 2 should be full size");
    test_assert(chunk_sizes[3] == 1000, "chunk 3 should be remainder");
}

static void test_caller_clamping() {
    const uint32_t size = 5 * k_large_buf_payload_max_size;

    loop_result_t result = simulate_with_protocol_max(
        size, k_large_buf_max_http_captured_bytes, k_large_buf_action_init);

    test_assert(result.num_chunks == 4, "should produce 4 chunks after caller clamping");
    test_assert(result.total_bytes_sent == k_large_buf_max_http_captured_bytes,
                "should send max_captured bytes");
}

static void test_loop_termination_conditions() {
    loop_result_t r1 = run_emit_chunks(1024, k_large_buf_action_init);

    test_assert(r1.num_chunks == 1, "small buffer terminates when all bytes consumed");
    test_assert(r1.total_bytes_sent == 1024, "all bytes are sent");

    loop_result_t r2 = simulate_with_protocol_max(
        100000, k_large_buf_max_http_captured_bytes, k_large_buf_action_init);

    test_assert(r2.total_bytes_sent <= k_large_buf_max_http_captured_bytes,
                "oversized buffer is clamped to max_captured by caller");
}

static void test_action_progression() {
    tcp_large_buffer_t large_buf;
    uint32_t available_bytes = 3 * k_large_buf_payload_max_size;

    large_buf.action = k_large_buf_action_init;

    enum large_buf_action actions[10];
    uint32_t action_count = 0;

    const uint32_t niter = (available_bytes / k_large_buf_payload_max_size) +
                           ((available_bytes % k_large_buf_payload_max_size) > 0);

    for (uint32_t b = 0; b < niter; b++) {
        const uint32_t read_size = available_bytes > k_large_buf_payload_max_size
                                       ? k_large_buf_payload_max_size
                                       : available_bytes;

        actions[action_count++] = large_buf.action;

        available_bytes -= read_size;

        // action set AFTER output, matching large_buf_emit_chunks
        large_buf.action = k_large_buf_action_append;
    }

    test_assert(actions[0] == k_large_buf_action_init, "first action should be init");
    test_assert(actions[1] == k_large_buf_action_append, "second action should be append");
    test_assert(actions[2] == k_large_buf_action_append, "third action should be append");
}

static void test_max_uint32() {
    const uint32_t size = UINT32_MAX;

    loop_result_t result = simulate_with_protocol_max(
        size, k_large_buf_max_http_captured_bytes, k_large_buf_action_init);

    test_assert(result.total_bytes_sent == k_large_buf_max_http_captured_bytes,
                "should clamp to max_captured");
    test_assert(result.num_chunks == 4, "should produce 4 chunks");
}

static void print_summary() {
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total Tests:  %u\n", stats.total_tests);
    printf("Passed:       %u\n", stats.passed_tests);
    printf("Failed:       %u\n", stats.failed_tests);
    printf("========================================\n");

    if (stats.failed_tests == 0) {
        printf("✓ All tests passed!\n");
    } else {
        printf("✗ Some tests failed!\n");
    }
}

typedef void (*test_func)();

typedef struct {
    const char *name;
    test_func func;
} test_spec_t;

#define TEST(x) {#x, test_##x},

static test_spec_t tests[] = {
    TEST(empty_buffer) TEST(small_buffer) TEST(exact_chunk_size) TEST(one_byte_over_chunk)
        TEST(slightly_over_chunk) TEST(exact_two_chunks) TEST(three_chunks) TEST(exact_max_captured)
            TEST(over_max_captured) TEST(very_large_buffer) TEST(boundary_minus_one)
                TEST(boundary_plus_one) TEST(with_append_action) TEST(chunk_distribution)
                    TEST(caller_clamping) TEST(loop_termination_conditions) TEST(action_progression)
                        TEST(max_uint32)};

int main() {
    printf("Large Buffer Loop Test Suite\n");
    printf("========================================\n");
    printf("Testing buffer chunking logic from protocol_common.h\n");
    printf("  k_large_buf_payload_max_size     = %d (16K)\n", k_large_buf_payload_max_size);
    printf("  k_large_buf_max_*_captured_bytes = %d (64K)\n", k_large_buf_max_http_captured_bytes);
    printf("  k_large_buf_max_size             = %d (32K)\n", k_large_buf_max_size);
    printf("========================================\n\n");

    for (uint32_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        g_test_name = tests[i].name;
        tests[i].func();
    }

    print_summary();

    return (stats.failed_tests == 0) ? 0 : 1;
}
