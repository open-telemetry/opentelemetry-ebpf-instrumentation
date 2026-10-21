// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static void *current_request;
static unsigned int deletions;

static long delete_request(void *map, const void *key) {
    current_request = NULL;
    deletions++;
    return 0;
}

#define bpf_map_delete_elem delete_request
#include <generictracer/maps/java_http1_requests.h>

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void) {
    g_bpf_java_http1_enabled = true;
    const pid_connection_info_t conn = {.pid = 42};
    java_http1_request_t a = {};
    java_http1_request_t b = {};
    current_request = &a;

    // A's release has already looked up and matched A. Another CPU consumes A
    // and installs B before that release reaches its deletion.
    java_http1_request_t *delayed_release = current_request;
    expect(java_http1_request_retire(&conn, &a), "the parser consumes A");
    current_request = &b;
    expect(!java_http1_request_retire(&conn, delayed_release),
           "A's delayed cleanup cannot retire twice");
    expect(current_request == &b, "A's delayed cleanup preserves B");
    expect(deletions == 1, "only the retirement winner deletes");
    expect(java_http1_request_retire(&conn, &b), "B remains independently releasable");
    expect(current_request == NULL, "a failed send releases its reservation");
    puts("Java HTTP/1 reservation lifecycle checks passed");
    return 0;
}
