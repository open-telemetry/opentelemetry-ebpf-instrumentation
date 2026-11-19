// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// sampling.h stamps each trace with its process's sampling decision, so the
// traceparent OBI propagates carries the decision its exporter applies. The
// decision must match the OpenTelemetry Go SDK samplers bit for bit, or OBI and
// SDK-instrumented services would split the same trace.
//
// Run from repo root:
//   make -C bpf/tests bpf_sampling && bpf/tests/bpf_sampling

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/sampling.h>

static const pid_info_t k_test_pid = {.host_pid = 9000, .user_pid = 4242, .ns = 42};

// the whole trace id ratio key space: TraceIDRatioBased(1)
static const u64 k_all_threshold = 1ULL << 63;
// half of it: TraceIDRatioBased(0.5)
static const u64 k_half_threshold = 1ULL << 62;

static sampler_t test_sampler;
static bool test_sampler_set;

static void *lookup_test_sampler(void *map, const void *key) {
    const pid_info_t *pid = key;
    if (map != &pid_samplers || !test_sampler_set || pid->host_pid != 0 ||
        pid->user_pid != k_test_pid.user_pid || pid->ns != k_test_pid.ns) {
        return NULL;
    }

    return &test_sampler;
}

static void use_sampler(u64 threshold, u8 parent_based) {
    test_sampler = (sampler_t){.threshold = threshold, .parent_based = parent_based};
    test_sampler_set = true;
}

static void use_no_sampler(void) {
    test_sampler_set = false;
}

// the trace id's last 8 bytes are the ratio key's source, big endian
static tp_info_t trace_with_low_bytes(u64 low_be) {
    tp_info_t tp = {};
    tp.trace_id[0] = 1;
    for (u32 i = 0; i < sizeof(low_be); i++) {
        tp.trace_id[TRACE_ID_SIZE_BYTES - 1 - i] = (unsigned char)(low_be >> (8 * i));
    }

    return tp;
}

static void expect(bool got, const char *message) {
    if (!got) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void test_ratio_key_matches_go_sdk(void) {
    // Go SDK: binary.BigEndian.Uint64(traceID[8:16]) >> 1
    const tp_info_t tp = trace_with_low_bytes(0x8000000000000003ULL);
    expect(trace_id_ratio_key(tp.trace_id) == 0x4000000000000001ULL,
           "the ratio key is the trace id's last 8 bytes, big endian, shifted right by one");
}

static void test_process_without_sampler_keeps_new_traces(void) {
    use_no_sampler();
    tp_info_t tp = trace_with_low_bytes(~0ULL);

    sample_new_trace_for_pid(&tp, &k_test_pid);

    expect(tp.flags == k_flag_sampled, "a process without a sampler samples the traces it starts");
}

static void test_ratio_sampler_decides_new_traces(void) {
    use_sampler(k_half_threshold, 1);
    tp_info_t below = trace_with_low_bytes((k_half_threshold - 1) << 1);
    tp_info_t at = trace_with_low_bytes(k_half_threshold << 1);

    sample_new_trace_for_pid(&below, &k_test_pid);
    sample_new_trace_for_pid(&at, &k_test_pid);

    expect(below.flags == k_flag_sampled, "a trace whose key is below the threshold is sampled");
    expect(at.flags == 0, "a trace whose key reaches the threshold is not sampled");
}

static void test_sampler_is_looked_up_by_pid(void) {
    use_sampler(0, 1);
    tp_info_t tp = trace_with_low_bytes(0);
    pid_info_t pid = k_test_pid;

    pid.user_pid++;
    sample_new_trace_for_pid(&tp, &pid);
    expect(tp.flags == k_flag_sampled, "another process's sampler does not apply");

    pid = k_test_pid;
    pid.ns++;
    sample_new_trace_for_pid(&tp, &pid);
    expect(tp.flags == k_flag_sampled, "the same pid in another namespace has its own sampler");

    pid = k_test_pid;
    pid.host_pid++;
    sample_new_trace_for_pid(&tp, &pid);
    expect(tp.flags == 0, "the namespace identity selects the sampler independently of host pid");
}

static void test_parent_based_sampler_keeps_remote_decision(void) {
    tp_info_t sampled = trace_with_low_bytes(0);
    sampled.flags = k_flag_sampled;
    // on its own, this sampler drops every trace
    use_sampler(0, 1);
    sample_remote_child_for_pid(&sampled, &k_test_pid);
    expect(sampled.flags == k_flag_sampled, "a parent based sampler keeps a sampled parent");

    tp_info_t unsampled = trace_with_low_bytes(0);
    unsampled.flags = 0;
    // on its own, this sampler keeps every trace
    use_sampler(k_all_threshold, 1);
    sample_remote_child_for_pid(&unsampled, &k_test_pid);
    expect(unsampled.flags == 0, "a parent based sampler keeps an unsampled parent");
}

static void test_other_samplers_decide_remote_children(void) {
    use_sampler(k_half_threshold, 0);
    tp_info_t unsampled_parent = trace_with_low_bytes(0);
    unsampled_parent.flags = 0;
    tp_info_t sampled_parent = trace_with_low_bytes(~0ULL);
    sampled_parent.flags = k_flag_sampled;

    sample_remote_child_for_pid(&unsampled_parent, &k_test_pid);
    sample_remote_child_for_pid(&sampled_parent, &k_test_pid);

    expect(unsampled_parent.flags == k_flag_sampled,
           "a sampler that is not parent based samples by the trace id");
    expect(sampled_parent.flags == 0, "a sampler that is not parent based drops by the trace id");
}

static void test_process_without_sampler_keeps_remote_decision(void) {
    use_no_sampler();
    tp_info_t tp = trace_with_low_bytes(0);
    tp.flags = 0;

    sample_remote_child_for_pid(&tp, &k_test_pid);

    expect(tp.flags == 0, "a process without a sampler keeps the parent's decision");
}

int main(void) {
    bpf_map_lookup_elem_hook = lookup_test_sampler;

    test_ratio_key_matches_go_sdk();
    test_process_without_sampler_keeps_new_traces();
    test_ratio_sampler_decides_new_traces();
    test_sampler_is_looked_up_by_pid();
    test_parent_based_sampler_keeps_remote_decision();
    test_other_samplers_decide_remote_children();
    test_process_without_sampler_keeps_remote_decision();

    printf("OK: %s\n", __FILE__);
    return 0;
}
