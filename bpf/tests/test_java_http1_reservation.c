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
    java_http1_request_t slot = {.state = 1};
    current_request = &slot;
    java_http1_request_t *delayed_release = &slot;

    expect(java_http1_request_retire(&conn, &slot, 1), "the parser consumes A");
    // Reuse the exact same physical storage for B, as preallocated maps do.
    slot = (java_http1_request_t){.state = 2};
    current_request = &slot;
    expect(!java_http1_request_retire(&conn, delayed_release, 1),
           "A's delayed cleanup cannot retire B at the same address");
    expect(current_request == &slot, "A's delayed cleanup preserves B");
    expect(slot.state == 2, "stale cleanup does not modify B's generation");
    expect(deletions == 1, "only the retirement winner deletes");
    expect(java_http1_request_retire(&conn, &slot, 2), "B remains independently releasable");
    expect(current_request == NULL, "a failed send releases its reservation");
    expect(slot.state == 0, "retirement frees the array slot");
    expect(!java_http1_request_retire(&conn, &slot, 2), "retirement cannot win twice");
    puts("Java HTTP/1 reservation lifecycle checks passed");
    return 0;
}
