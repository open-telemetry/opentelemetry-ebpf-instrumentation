// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_http_connection_reuse && bpf/tests/test_http_connection_reuse
// Run from bpf/tests:
//   make test_http_connection_reuse && ./test_http_connection_reuse

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

static http_info_t in_flight_client_request(void) {
    http_info_t info = {};
    info.type = EVENT_HTTP_CLIENT;
    info.start_monotime_ns = 1000;
    info.pid.host_pid = 4242;

    return info;
}

static http_info_t in_flight_server_request(void) {
    http_info_t info = in_flight_client_request();
    info.type = EVENT_HTTP_REQUEST;

    return info;
}

// The response travels opposite the request: inbound for a call this process made,
// outbound for one it served.
static void test_response_direction_follows_the_record_type(void) {
    const http_info_t client = in_flight_client_request();
    const http_info_t server = in_flight_server_request();

    assert_true(http_response_direction(&client, TCP_RECV),
                "a client's response arrives on a read");
    assert_true(!http_response_direction(&client, TCP_SEND),
                "a client's own request going out is not its response");
    assert_true(http_response_direction(&server, TCP_SEND), "a server's response goes out");
    assert_true(!http_response_direction(&server, TCP_RECV),
                "a request arriving at a server is not its response");
}

// The unparsed remainder of a response used to be added to the request's length, which
// left the record indistinguishable from one still waiting to be answered.
static void test_unparsed_response_is_recognized_not_counted_as_request(void) {
    const http_info_t client = in_flight_client_request();
    const http_info_t server = in_flight_server_request();

    assert_true(unparsed_response_buffer(&client, TCP_RECV),
                "an unrecognized read is the client's response");
    assert_true(!unparsed_response_buffer(&client, TCP_SEND),
                "an unrecognized write is more of the client's request");
    assert_true(unparsed_response_buffer(&server, TCP_SEND),
                "an unrecognized write is the server's response");
    assert_true(!unparsed_response_buffer(&server, TCP_RECV),
                "an unrecognized read is more of the server's request");
}

// A response split across several unparsed buffers ends the record at the last of them.
static void test_marking_advances_the_end_with_each_buffer(void) {
    http_info_t info = in_flight_client_request();

    note_unread_response(&info, 3000);
    assert_true(response_unread(&info), "a marked record is holding an unread response");
    assert_true(info.status == 0, "an unread response reports no status");
    assert_true(info.end_monotime_ns == 3000, "the record ends when the response arrived");
    assert_true(!still_reading(&info), "a marked record is no longer waiting on a response");

    assert_true(unparsed_response_buffer(&info, TCP_RECV),
                "a further unrecognized read is still this response");

    note_unread_response(&info, 4000);
    assert_true(info.end_monotime_ns == 4000, "the end advances to the last buffer seen");
}

// The whole point of the marker: the record survives the next request on the connection.
// Before it, only status != 0 got a record out, so every reused connection lost the call
// that came before.
static void test_marked_record_is_emitted_where_an_unmarked_one_was_dropped(void) {
    http_info_t waiting = in_flight_client_request();
    assert_true(!http_info_emittable(&waiting),
                "a request still waiting on its response is not emitted");

    http_info_t answered_unparsed = in_flight_client_request();
    note_unread_response(&answered_unparsed, 3000);
    assert_true(http_info_emittable(&answered_unparsed),
                "a request whose response went unparsed is emitted");
    assert_true(!http_info_complete(&answered_unparsed),
                "an unread response is not mistaken for an observed one");
}

// A record still waiting when the next request takes the connection is reported too,
// without a duration it cannot vouch for.
static void test_displaced_record_is_reported(void) {
    http_info_t waiting = in_flight_client_request();
    waiting.resp_len = 17;

    note_displaced_by_next_request(&waiting, 5000);

    assert_true(waiting.response_observation == http_response_received,
                "a displaced request reports that its response was never read");
    assert_true(waiting.status == 0, "a displaced request reports no status");
    assert_true(waiting.end_monotime_ns != 0, "a displaced request is ended");
    assert_true(waiting.resp_len == 0, "a displaced request claims no response body");
    assert_true(http_info_emittable(&waiting), "a displaced request is emitted");
}

// Displacement must not overwrite a record that already timed its own response, nor
// disturb one that parsed a status.
static void test_displacement_leaves_finished_records_alone(void) {
    http_info_t unread = in_flight_client_request();
    note_unread_response(&unread, 3000);

    note_displaced_by_next_request(&unread, 5000);
    assert_true(unread.response_observation == http_response_unread,
                "a record that saw its response keeps that observation");
    assert_true(unread.end_monotime_ns == 3000, "a record that saw its response keeps its end");

    http_info_t answered = in_flight_client_request();
    answered.status = 200;
    answered.end_monotime_ns = 2000;

    note_displaced_by_next_request(&answered, 5000);
    assert_true(answered.status == 200, "an answered request keeps its status");
    assert_true(answered.end_monotime_ns == 2000, "an answered request keeps its end");
    assert_true(answered.response_observation == http_response_parsed,
                "an answered request stays parsed");
}

// The next client call on a reused connection is not a self reference. The helper exists
// so a server call can inherit the parent of the client call it answers, which is only
// possible when a process calls itself and both legs share the connection tuple.
//
// A record whose response went unparsed now stays here to be reported, so an outbound
// request finds it where it used to find nothing. Adopting its parent would hang the new
// call off the previous call's parent and leave the request that made it childless.
static void test_next_client_call_does_not_self_reference(void) {
    http_info_t answered_unparsed = in_flight_client_request();
    note_unread_response(&answered_unparsed, 3000);

    assert_true(!self_reference_candidate(&answered_unparsed, EVENT_HTTP_CLIENT),
                "the next client call on the connection does not adopt the previous parent");

    http_info_t waiting = in_flight_client_request();
    assert_true(!self_reference_candidate(&waiting, EVENT_HTTP_CLIENT),
                "a client call does not adopt the parent of one still in flight");
}

// The case the helper is for must keep working: the process called itself, so the server
// leg arrives on the same tuple and takes the parent the client call carried.
static void test_server_request_still_self_references(void) {
    http_info_t waiting = in_flight_client_request();
    assert_true(self_reference_candidate(&waiting, EVENT_HTTP_REQUEST),
                "a server request adopts the parent of the client call it answers");

    http_info_t answered_unparsed = in_flight_client_request();
    note_unread_response(&answered_unparsed, 3000);
    assert_true(self_reference_candidate(&answered_unparsed, EVENT_HTTP_REQUEST),
                "an unparsed response does not stop the server leg from self referencing");
}

// Only an unfinished client record is worth referencing. A finished one belongs to a
// call that already ended, and a server record is not something a request self references
// through at all.
static void test_self_reference_ignores_finished_and_server_records(void) {
    http_info_t answered = in_flight_client_request();
    answered.status = 200;
    assert_true(!self_reference_candidate(&answered, EVENT_HTTP_REQUEST),
                "a call that already reported its status is not self referenced");

    http_info_t served = in_flight_server_request();
    assert_true(!self_reference_candidate(&served, EVENT_HTTP_REQUEST),
                "a server record is not the client call a request self references through");
}

int main(void) {
    test_response_direction_follows_the_record_type();
    test_unparsed_response_is_recognized_not_counted_as_request();
    test_marking_advances_the_end_with_each_buffer();
    test_marked_record_is_emitted_where_an_unmarked_one_was_dropped();
    test_displaced_record_is_reported();
    test_displacement_leaves_finished_records_alone();
    test_next_client_call_does_not_self_reference();
    test_server_request_still_self_references();
    test_self_reference_ignores_finished_and_server_records();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
