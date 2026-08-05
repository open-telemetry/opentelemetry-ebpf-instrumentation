// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>

#include <bpfcore/bpf_helpers.h>

static uint64_t test_start_boottime = 123456789ULL;

static inline uint64_t test_current_start_boottime(void) {
    return test_start_boottime;
}

static inline uint64_t test_pid_tgid(void) {
    return 42ULL << 32;
}

#define OBI_CURRENT_PROCESS_START_BOOTTIME_NS() test_current_start_boottime()
#define bpf_get_current_pid_tgid test_pid_tgid

#include <common/process_incarnation.h>

static unsigned int failures;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_u64(uint64_t want, uint64_t got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr,
            "%s: want %llu, got %llu\n",
            message,
            (unsigned long long)want,
            (unsigned long long)got);
    failures++;
}

int main(void) {
    const uint64_t rounded = test_start_boottime - (test_start_boottime % k_process_clock_tick_ns);
    assert_u64(rounded,
               current_process_start_time_ns(),
               "userspace-bound start time remains clock-tick rounded");
    assert_bool(1,
                process_incarnation_matches_current(42, rounded),
                "rounded /proc identity matches the current process");
    assert_bool(1,
                process_incarnation_matches_current_exact(42, test_start_boottime),
                "full BPF-only identity matches its exact process");

    test_start_boottime++;
    assert_bool(1,
                process_incarnation_matches_current(42, rounded),
                "sub-tick process change remains indistinguishable to /proc identity");
    assert_bool(0,
                process_incarnation_matches_current_exact(42, test_start_boottime - 1),
                "exact transport identity distinguishes sub-tick process starts");
    return failures ? 1 : 0;
}
