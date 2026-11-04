// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/http_info.h>
#include <common/ringbuf.h>
#include <maps/ongoing_http.h>

static http_info_t old_slot;
static http_info_t replacement;
static http_info_t emitted;
static http_info_t *current;
static unsigned int submissions;

long replace_and_recycle(void *map, const void *key, const void *value, u64 flags) {
    (void)map;
    (void)key;
    (void)flags;
    replacement = *(const http_info_t *)value;
    current = &replacement;
    // Model another CPU reusing the old LRU node after map replacement.
    old_slot = (http_info_t){.task_tid = 200};
    old_slot.tp.trace_id[0] = 0xbb;
    old_slot.tp.span_id[0] = 0xcc;
    return 0;
}

static long
output_event(void *ringbuf, void *event, unsigned long long size, unsigned long long flags) {
    (void)ringbuf;
    (void)flags;
    memcpy(&emitted, event, size);
    submissions++;
    return 0;
}

#define bpf_map_update_elem replace_and_recycle
#include <generictracer/http_event.h>

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void) {
    bpf_ringbuf_output_hook = output_event;
    old_slot = (http_info_t){.start_monotime_ns = 1, .status = 200, .task_tid = 100};
    old_slot.pid.host_pid = 42;
    old_slot.tp.trace_id[0] = 0x11;
    old_slot.tp.span_id[0] = 0x22;
    current = &old_slot;
    submit_http_event(current);
    expect(submissions == 1, "the completed request is exported once");
    expect(emitted.flags == k_event_type_k_http_request, "the exported event has the HTTP tag");
    expect(emitted.tp.trace_id[0] == 0x11, "the exported trace belongs to the submitted request");
    expect(emitted.tp.span_id[0] == 0x22, "the exported span belongs to the submitted request");
    expect(emitted.task_tid == 100, "the exported owner belongs to the submitted request");
    expect(old_slot.task_tid == 100, "the caller retains its request for cleanup");
    expect(current->submitted == 1, "submission is visible through the existing map entry");
    submit_http_event(current);
    expect(submissions == 1, "a second completion does not export a duplicate");
    puts("HTTP submission preserves its request identity");
    return 0;
}
