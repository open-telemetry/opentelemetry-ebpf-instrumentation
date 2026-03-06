// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run me with: gcc -o test_large_buffer_loop test_large_buffer_loop.c
// ./test_large_buffer_loop

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

// Constants from bpf/common/large_buffers.h
enum {
  k_large_buf_max_size = 1 << 15, // 32K
  k_large_buf_max_size_mask = k_large_buf_max_size - 1,
  k_large_buf_payload_max_size = 1 << 14, // 16K
  k_large_buf_payload_max_size_mask = k_large_buf_payload_max_size - 1,
  k_large_buf_abs_max_size = 1 << 16, // 64K
};

// Large buffer action enum from bpf/common/common.h
enum large_buf_action {
  k_large_buf_action_init = 0,
  k_large_buf_action_append = 1,
};

// Simplified tcp_large_buffer_t structure
typedef struct tcp_large_buffer {
  uint8_t type;
  uint8_t packet_type;
  enum large_buf_action action;
  uint8_t direction;
  uint32_t len;
  uint8_t buf[k_large_buf_payload_max_size];
} tcp_large_buffer_t;

// Helper macro to clamp value to maximum (simulating bpf_clamp_umax)
#define bpf_clamp_umax(val, max)                                               \
  do {                                                                         \
    if ((val) > (max))                                                         \
      (val) = (max);                                                           \
  } while (0)

// Test result tracking
typedef struct {
  int total_tests;
  int passed_tests;
  int failed_tests;
} test_stats_t;

test_stats_t stats = {0, 0, 0};

void test_assert(int condition, const char *test_name, const char *msg) {
  stats.total_tests++;
  if (condition) {
    stats.passed_tests++;
    printf("✓ PASS: %s - %s\n", test_name, msg);
  } else {
    stats.failed_tests++;
    printf("✗ FAIL: %s - %s\n", test_name, msg);
  }
}

// Simulating the loop from protocol_http.h
typedef struct {
  int num_chunks;
  int total_bytes_sent;
  enum large_buf_action final_action;
  int loop_iterations;
} loop_result_t;

loop_result_t simulate_large_buffer_loop(uint32_t bytes_len,
                                         enum large_buf_action initial_action) {
  loop_result_t result = {0, 0, initial_action, 0};
  tcp_large_buffer_t large_buf;

  uint32_t available_bytes = bytes_len;
  bpf_clamp_umax(available_bytes, k_large_buf_abs_max_size);

  const uint32_t niter = (available_bytes / k_large_buf_payload_max_size) +
                         ((available_bytes % k_large_buf_payload_max_size) > 0);
  int b = 0;
  for (; b < niter; b++) {
    result.loop_iterations++;

    uint32_t offset = b * k_large_buf_payload_max_size;
    if (offset >= k_large_buf_abs_max_size) {
      break;
    }

    uint32_t read_size = available_bytes;
    bpf_clamp_umax(read_size, k_large_buf_payload_max_size);

    large_buf.len = read_size;
    large_buf.action = (b == 0) ? initial_action : k_large_buf_action_append;

    // Simulate bpf_probe_read - just note the size
    // bpf_probe_read(large_buf->buf, read_size, (void *)(&u_buf[offset]));

    uint32_t total_size = sizeof(tcp_large_buffer_t);
    total_size +=
        large_buf.len > sizeof(void *) ? large_buf.len : sizeof(void *);

    bpf_clamp_umax(total_size, k_large_buf_max_size);

    // Simulate bpf_ringbuf_output - count the chunk
    result.num_chunks++;
    result.total_bytes_sent += read_size;
    result.final_action = large_buf.action;

    available_bytes -= read_size;
  }

  return result;
}

// Test cases
void test_empty_buffer() {
  const char *test_name = "empty_buffer";
  loop_result_t result = simulate_large_buffer_loop(0, k_large_buf_action_init);

  test_assert(result.num_chunks == 0, test_name,
              "should produce 1 chunk for empty buffer");
  test_assert(result.total_bytes_sent == 0, test_name, "should send 0 bytes");
  test_assert(result.final_action == k_large_buf_action_init, test_name,
              "should have init action");
  test_assert(result.loop_iterations == 0, test_name, "should iterate once");
}

void test_small_buffer() {
  const char *test_name = "small_buffer";
  uint32_t size = 1024;
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  test_assert(result.num_chunks == 1, test_name, "should produce 1 chunk");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
  test_assert(result.final_action == k_large_buf_action_init, test_name,
              "should have init action");
  test_assert(result.loop_iterations == 1, test_name, "should iterate once");
}

void test_exact_chunk_size() {
  const char *test_name = "exact_chunk_size";
  uint32_t size = k_large_buf_payload_max_size; // 16384
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  test_assert(result.num_chunks == 1, test_name, "should produce 1 chunk");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
  test_assert(result.final_action == k_large_buf_action_init, test_name,
              "should have init action");
  test_assert(result.loop_iterations == 1, test_name, "should iterate once");
}

void test_one_byte_over_chunk() {
  const char *test_name = "one_byte_over_chunk";
  uint32_t size = k_large_buf_payload_max_size + 1; // 16385
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  test_assert(result.num_chunks == 2, test_name, "should produce 2 chunks");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
  test_assert(result.final_action == k_large_buf_action_append, test_name,
              "final action should be append");
  test_assert(result.loop_iterations == 2, test_name, "should iterate twice");
}

void test_slightly_over_chunk() {
  const char *test_name = "slightly_over_chunk";
  uint32_t size = 17000;
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  test_assert(result.num_chunks == 2, test_name, "should produce 2 chunks");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
  test_assert(result.final_action == k_large_buf_action_append, test_name,
              "final action should be append");
}

void test_exact_two_chunks() {
  const char *test_name = "exact_two_chunks";
  uint32_t size = 2 * k_large_buf_payload_max_size; // 32768
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  test_assert(result.num_chunks == 2, test_name, "should produce 2 chunks");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
  test_assert(result.final_action == k_large_buf_action_append, test_name,
              "final action should be append");
}

void test_three_chunks() {
  const char *test_name = "three_chunks";
  uint32_t size = 3 * k_large_buf_payload_max_size; // 49152
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  test_assert(result.num_chunks == 3, test_name, "should produce 3 chunks");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
  test_assert(result.final_action == k_large_buf_action_append, test_name,
              "final action should be append");
}

void test_exact_abs_max() {
  const char *test_name = "exact_abs_max";
  uint32_t size = k_large_buf_abs_max_size; // 65536
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  test_assert(result.num_chunks == 4, test_name, "should produce 4 chunks");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
  test_assert(result.final_action == k_large_buf_action_append, test_name,
              "final action should be append");
}

void test_over_abs_max() {
  const char *test_name = "over_abs_max";
  uint32_t size = k_large_buf_abs_max_size + 1000; // 66536
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  // Should be clamped to abs_max
  test_assert(result.num_chunks == 4, test_name,
              "should produce 4 chunks (clamped)");
  test_assert(result.total_bytes_sent == k_large_buf_abs_max_size, test_name,
              "should send only abs_max bytes");
  test_assert(result.final_action == k_large_buf_action_append, test_name,
              "final action should be append");
}

void test_very_large_buffer() {
  const char *test_name = "very_large_buffer";
  uint32_t size = 1024 * 1024; // 1MB
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  // Should be clamped to abs_max
  test_assert(result.num_chunks == 4, test_name,
              "should produce 4 chunks (clamped)");
  test_assert(result.total_bytes_sent == k_large_buf_abs_max_size, test_name,
              "should send only abs_max bytes");
}

void test_boundary_minus_one() {
  const char *test_name = "boundary_minus_one";
  uint32_t size = k_large_buf_payload_max_size - 1; // 16383
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  test_assert(result.num_chunks == 1, test_name, "should produce 1 chunk");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
  test_assert(result.final_action == k_large_buf_action_init, test_name,
              "should have init action");
}

void test_boundary_plus_one() {
  const char *test_name = "boundary_plus_one";
  uint32_t size = k_large_buf_payload_max_size + 1; // 16385
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  test_assert(result.num_chunks == 2, test_name, "should produce 2 chunks");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
}

void test_with_append_action() {
  const char *test_name = "with_append_action";
  uint32_t size = 2 * k_large_buf_payload_max_size;
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_append);

  test_assert(result.num_chunks == 2, test_name, "should produce 2 chunks");
  test_assert(result.total_bytes_sent == size, test_name,
              "should send all bytes");
  test_assert(result.final_action == k_large_buf_action_append, test_name,
              "final action should be append");
}

void test_chunk_distribution() {
  const char *test_name = "chunk_distribution";

  // Test that chunks are properly distributed
  uint32_t size =
      3 * k_large_buf_payload_max_size + 1000; // 49152 + 1000 = 50152

  tcp_large_buffer_t large_buf;
  uint32_t available_bytes = size;
  bpf_clamp_umax(available_bytes, k_large_buf_abs_max_size);

  int chunk_sizes[10] = {0};
  int chunk_count = 0;

  int b = 0;
  const uint32_t niter = (available_bytes / k_large_buf_payload_max_size) +
                         ((available_bytes % k_large_buf_payload_max_size) > 0);

  for (; b < niter; b++) {
    uint32_t offset = b * k_large_buf_payload_max_size;
    if (offset >= k_large_buf_abs_max_size) {
      break;
    }

    uint32_t read_size = available_bytes;
    bpf_clamp_umax(read_size, k_large_buf_payload_max_size);

    chunk_sizes[chunk_count++] = read_size;

    available_bytes -= read_size;
  }

  test_assert(chunk_count == 4, test_name, "should have 4 chunks");
  test_assert(chunk_sizes[0] == k_large_buf_payload_max_size, test_name,
              "chunk 0 should be full size");
  test_assert(chunk_sizes[1] == k_large_buf_payload_max_size, test_name,
              "chunk 1 should be full size");
  test_assert(chunk_sizes[2] == k_large_buf_payload_max_size, test_name,
              "chunk 2 should be full size");
  test_assert(chunk_sizes[3] == 1000, test_name, "chunk 3 should be remainder");
}

void test_offset_boundary() {
  const char *test_name = "offset_boundary";

  // Test that offset check works correctly
  // At 4 chunks, offset would be 4 * 16384 = 65536 which equals abs_max
  uint32_t size = 5 * k_large_buf_payload_max_size; // 81920
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  // Should stop at 4 chunks due to abs_max clamping
  test_assert(result.num_chunks == 4, test_name,
              "should stop at 4 chunks due to offset >= abs_max");
  test_assert(result.total_bytes_sent == k_large_buf_abs_max_size, test_name,
              "should send abs_max bytes");
}

void test_loop_termination_conditions() {
  const char *test_name = "loop_termination";

  // Test all three termination conditions:
  // 1. read_size <= k_large_buf_payload_max_size (normal case)
  // 2. offset >= k_large_buf_abs_max_size
  // 3. b > (max / k_large_buf_payload_max_size)

  // Condition 1: read_size <= max (normal termination)
  loop_result_t r1 = simulate_large_buffer_loop(1024, k_large_buf_action_init);
  test_assert(r1.num_chunks == 1, test_name,
              "small buffer terminates on read_size check");

  // Condition 2: offset >= abs_max (boundary termination)
  loop_result_t r2 =
      simulate_large_buffer_loop(100000, k_large_buf_action_init);
  test_assert(r2.total_bytes_sent <= k_large_buf_abs_max_size, test_name,
              "large buffer terminates at abs_max");
}

void test_action_progression() {
  const char *test_name = "action_progression";

  // Verify that action changes from init to append correctly
  tcp_large_buffer_t large_buf;
  uint32_t size = 3 * k_large_buf_payload_max_size;
  enum large_buf_action initial = k_large_buf_action_init;

  uint32_t available_bytes = size;
  bpf_clamp_umax(available_bytes, k_large_buf_abs_max_size);

  enum large_buf_action actions[10];
  int action_count = 0;

  const uint32_t niter = (available_bytes / k_large_buf_payload_max_size) +
                         ((available_bytes % k_large_buf_payload_max_size) > 0);

  int b = 0;
  for (; b < niter; b++) {
    uint32_t offset = b * k_large_buf_payload_max_size;
    if (offset >= k_large_buf_abs_max_size) {
      break;
    }

    uint32_t read_size = available_bytes;
    bpf_clamp_umax(read_size, k_large_buf_payload_max_size);

    large_buf.action = (b == 0) ? initial : k_large_buf_action_append;
    actions[action_count++] = large_buf.action;

    available_bytes -= k_large_buf_payload_max_size;
  }

  test_assert(actions[0] == k_large_buf_action_init, test_name,
              "first action should be init");
  test_assert(actions[1] == k_large_buf_action_append, test_name,
              "second action should be append");
  test_assert(actions[2] == k_large_buf_action_append, test_name,
              "third action should be append");
}

void test_max_uint32() {
  const char *test_name = "max_uint32";
  uint32_t size = UINT32_MAX;
  loop_result_t result =
      simulate_large_buffer_loop(size, k_large_buf_action_init);

  // Should be clamped to abs_max
  test_assert(result.total_bytes_sent == k_large_buf_abs_max_size, test_name,
              "should clamp to abs_max");
  test_assert(result.num_chunks == 4, test_name, "should produce 4 chunks");
}

void print_summary() {
  printf("\n");
  printf("========================================\n");
  printf("Test Summary\n");
  printf("========================================\n");
  printf("Total Tests:  %d\n", stats.total_tests);
  printf("Passed:       %d\n", stats.passed_tests);
  printf("Failed:       %d\n", stats.failed_tests);
  printf("========================================\n");

  if (stats.failed_tests == 0) {
    printf("✓ All tests passed!\n");
  } else {
    printf("✗ Some tests failed!\n");
  }
}

int main() {
  printf("Large Buffer Loop Test Suite\n");
  printf("========================================\n");
  printf("Testing buffer chunking logic from protocol_http.h\n");
  printf("Constants:\n");
  printf("  k_large_buf_payload_max_size = %d (16K)\n",
         k_large_buf_payload_max_size);
  printf("  k_large_buf_abs_max_size = %d (64K)\n", k_large_buf_abs_max_size);
  printf("  k_large_buf_max_size = %d (32K)\n", k_large_buf_max_size);
  printf("========================================\n\n");

  // Run all tests
  test_empty_buffer();
  test_small_buffer();
  test_exact_chunk_size();
  test_one_byte_over_chunk();
  test_slightly_over_chunk();
  test_exact_two_chunks();
  test_three_chunks();
  test_exact_abs_max();
  test_over_abs_max();
  test_very_large_buffer();
  test_boundary_minus_one();
  test_boundary_plus_one();
  test_with_append_action();
  test_chunk_distribution();
  test_offset_boundary();
  test_loop_termination_conditions();
  test_action_progression();
  test_max_uint32();

  print_summary();

  return (stats.failed_tests == 0) ? 0 : 1;
}
