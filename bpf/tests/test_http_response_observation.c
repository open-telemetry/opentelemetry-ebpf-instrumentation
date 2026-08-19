// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_http_response_observation && bpf/tests/test_http_response_observation
// Run from bpf/tests:
//   make test_http_response_observation && ./test_http_response_observation

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <common/http_info.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

static http_info_t in_flight_request(void) {
    http_info_t info = {};
    info.start_monotime_ns = 1000;
    info.pid.host_pid = 4242;

    return info;
}

static void test_in_flight_request_is_not_emitted(void) {
    http_info_t info = in_flight_request();

    assert_true(!http_info_complete(&info), "an unanswered request is not complete");
    assert_true(!http_info_emittable(&info), "an unanswered request is not emitted");
    assert_true(still_reading(&info), "an unanswered request is still reading");
}

static void test_answered_request_is_emitted(void) {
    http_info_t info = in_flight_request();
    info.status = 200;
    info.end_monotime_ns = 2000;

    assert_true(http_info_complete(&info), "an answered request is complete");
    assert_true(http_info_emittable(&info), "an answered request is emitted");
    assert_true(!still_reading(&info), "an answered request is no longer reading");
}

static void test_unobserved_response_is_emitted_without_a_status(void) {
    http_info_t info = in_flight_request();
    info.response_observation = http_response_silent;
    info.end_monotime_ns = 2000;

    assert_true(info.status == 0, "an unobserved response reports no status");
    assert_true(http_info_emittable(&info), "an unobserved response is still emitted");
    assert_true(!http_info_complete(&info),
                "an unobserved response is not mistaken for an observed one");
    assert_true(!still_reading(&info), "an unobserved response is no longer reading");
}

static void test_marker_alone_is_not_enough(void) {
    http_info_t info = {};
    info.response_observation = http_response_silent;

    assert_true(!http_info_emittable(&info), "a marked record with no start time is not emitted");

    info.start_monotime_ns = 1000;
    assert_true(!http_info_emittable(&info), "a marked record with no pid is not emitted");

    info.pid.host_pid = 4242;
    assert_true(http_info_emittable(&info), "a marked record with start time and pid is emitted");
}

// Measured against a peer that closes without answering: a bare FIN advanced
// bytes_received by exactly 1, a reset by 0, and a real response by its length plus the
// FIN's byte.
static void test_response_bytes_tolerate_the_fin_byte(void) {
    assert_true(!http_response_bytes_advanced(0, 0), "an untouched connection saw no response");
    assert_true(!http_response_bytes_advanced(0, 1),
                "a bare FIN on a fresh connection is not a response");
    assert_true(http_response_bytes_advanced(0, 2),
                "one payload byte plus the FIN byte is a response");

    // The case #3040 came from: a connection that has already carried an exchange is
    // nowhere near zero when the request that goes unanswered is written to it.
    assert_true(!http_response_bytes_advanced(4096, 4097),
                "a bare FIN on a reused connection is not a response");
    assert_true(!http_response_bytes_advanced(4096, 4096),
                "a reused connection with no further bytes saw no response");
    assert_true(http_response_bytes_advanced(4096, 4098),
                "payload past the snapshot on a reused connection is a response");
    assert_true(http_response_bytes_advanced(4096, 9000),
                "a full response past the snapshot is a response");

    assert_true(!http_response_bytes_advanced(4096, 1),
                "a counter below its snapshot is no advance");
    assert_true(!http_response_bytes_advanced(1, 0), "a one-byte regression is no advance");
}

static void test_observation_at_close_names_both_cases(void) {
    assert_true(http_response_observation_at_close(100, 5000) == http_response_received,
                "bytes past the snapshot mean the peer answered and OBI did not parse it");
    assert_true(http_response_observation_at_close(100, 101) == http_response_silent,
                "a FIN alone means nothing came back");
    assert_true(http_response_observation_at_close(100, 100) == http_response_silent,
                "no movement at all means nothing came back");

    // A TLS uprobe holds no socket, so the baseline stays zero and the connection's
    // whole history reads as an advance.
    assert_true(http_response_observation_at_close(0, 5000) == http_response_received,
                "an unsnapshotted record with traffic degrades to unparsed, not to absent");
    assert_true(http_response_observation_at_close(0, 0) == http_response_silent,
                "an unsnapshotted record with no traffic at all is still absent");
}

// The marker takes a former padding byte at the tail, and the snapshot sits with the
// other u64s where it costs no padding of its own. Assert both, so a later field is not
// added in the belief the tail has room.
static void test_struct_grew_by_exactly_the_snapshot(void) {
    assert_true(sizeof(http_info_t) % 8 == 0, "http_info_t stays 8-byte aligned in size");
    assert_true(offsetof(http_info_t, response_bytes_at_request) % sizeof(u64) == 0,
                "the snapshot is aligned, so it added no padding beyond its own word");
    assert_true(offsetof(http_info_t, response_observation) + sizeof(u8) == sizeof(http_info_t),
                "the marker is the record's last byte, in padding that already existed");
}

// Both outcomes travel the identical path out. Userspace decides what to do with the
// difference.
static void test_predicates_do_not_notice_which_unobserved_case(void) {
    http_info_t unparsed = in_flight_request();
    unparsed.response_observation = http_response_received;

    http_info_t absent = in_flight_request();
    absent.response_observation = http_response_silent;

    assert_true(http_info_emittable(&unparsed) && http_info_emittable(&absent),
                "both unobserved outcomes are emittable");
    assert_true(!http_info_complete(&unparsed) && !http_info_complete(&absent),
                "neither unobserved outcome is mistaken for an observed one");
    assert_true(!still_reading(&unparsed) && !still_reading(&absent),
                "neither unobserved outcome is still reading");
}

int main(void) {
    test_in_flight_request_is_not_emitted();
    test_answered_request_is_emitted();
    test_unobserved_response_is_emitted_without_a_status();
    test_marker_alone_is_not_enough();
    test_response_bytes_tolerate_the_fin_byte();
    test_observation_at_close_names_both_cases();
    test_predicates_do_not_notice_which_unobserved_case();
    test_struct_grew_by_exactly_the_snapshot();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
