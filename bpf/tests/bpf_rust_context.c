// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <common/rust_task.h>

enum { k_entries = 32 };

typedef struct entry {
    void *map;
    rust_task_key_t key;
    union {
        tp_info_pid_t value;
        rust_http_request_t request;
    };
} entry_t;

static entry_t entries[k_entries];
static bool enabled = true;
static rust_capabilities_t capabilities = {
    .task_context = 1, .client_context = 1, .tokio_runtime = 1};
static rust_thread_state_t threads[3];
static const u64 ids[] = {1ULL << 32 | 1, 1ULL << 32 | 2, 2ULL << 32 | 3};
static u64 h2_sender = 1234;
static rust_task_key_t h2_task;
static rust_h2_key_t h2_key;
static rust_http_request_t h2_request;

static void *lookup(void *map, const void *key) {
    if (map == &rust_capabilities) {
        return enabled ? &capabilities : NULL;
    }
    if (map == &rust_threads) {
        for (u32 i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            if (*(const u64 *)key == ids[i]) {
                return &threads[i];
            }
        }
        return NULL;
    }
    if (map == &rust_h2_tasks) {
        return memcmp(key, &h2_task, sizeof(h2_task)) == 0 ? &h2_sender : NULL;
    }
    if (map == &rust_h2_requests) {
        return memcmp(key, &h2_key, sizeof(h2_key)) == 0 ? &h2_request : NULL;
    }
    for (u32 i = 0; i < k_entries; i++) {
        if (entries[i].map == map && memcmp(&entries[i].key, key, sizeof(entries[i].key)) == 0) {
            return &entries[i].value;
        }
    }
    return NULL;
}

static long store(void *map, const void *key, const void *value, unsigned long long flags) {
    (void)flags;
    void *existing = lookup(map, key);
    u32 size = sizeof(tp_info_pid_t);
    if (map == &rust_http1_requests) {
        size = sizeof(rust_http_request_t);
    } else if (map == &rust_io_connections) {
        size = sizeof(ssl_pid_connection_info_t);
    }
    if (existing) {
        memcpy(existing, value, size);
        return 0;
    }
    for (u32 i = 0; i < k_entries; i++) {
        if (!entries[i].map) {
            entries[i].map = map;
            entries[i].key = *(const rust_task_key_t *)key;
            memcpy(&entries[i].value, value, size);
            return 0;
        }
    }
    assert(false);
    return -1;
}

static long erase(void *map, const void *key) {
    for (u32 i = 0; i < k_entries; i++) {
        if (entries[i].map == map && memcmp(&entries[i].key, key, sizeof(entries[i].key)) == 0) {
            entries[i].map = NULL;
        }
    }
    return 0;
}

static void run_task(u32 thread, u64 task) {
    threads[thread] = (rust_thread_state_t){.tasks = {task}, .depth = 1};
}

static void expect_context(u32 thread, u8 trace) {
    const tp_info_pid_t *context = rust_current_context(ids[thread]);
    assert(context);
    assert(context->valid == (trace != 0));
    assert(context->tp.trace_id[0] == trace);
}

int main(void) {
    const u32 pid = obi_pid(ids[0]);
    bpf_map_lookup_elem_hook = lookup;
    bpf_map_update_elem_hook = store;
    bpf_map_delete_elem_hook = erase;
    run_task(0, 100);
    const tp_info_pid_t parent = {.tp = {.trace_id = {42}}, .valid = 1};
    rust_set_context(ids[0], &parent);

    const rust_task_key_t child = {.pid = pid, .addr = 200};
    rust_copy_context(ids[0], &rust_task_context, &child);
    run_task(1, child.addr);
    expect_context(1, 42);

    // Two messages remain independent even when dequeued in reverse order.
    const rust_task_key_t slot1 = {.pid = pid, .addr = 1000};
    const rust_task_key_t slot2 = {.pid = pid, .addr = 2000};
    rust_copy_context(ids[0], &rust_channel_context, &slot1);
    const tp_info_pid_t other = {.tp = {.trace_id = {24}}, .valid = 1};
    rust_set_context(ids[0], &other);
    rust_copy_context(ids[0], &rust_channel_context, &slot2);
    rust_adopt_channel_context(ids[1], &slot2);
    expect_context(1, 24);
    rust_adopt_channel_context(ids[1], &slot1);
    expect_context(1, 42);
    assert(!lookup(&rust_channel_context, &slot1));

    // A reused slot and an evicted message must clear the driver's old parent.
    run_task(0, 300);
    rust_copy_context(ids[0], &rust_channel_context, &slot2);
    rust_adopt_channel_context(ids[1], &slot2);
    expect_context(1, 0);
    rust_set_context(ids[1], &parent);
    rust_adopt_channel_context(ids[1], &slot2);
    expect_context(1, 0);

    // Replacing a task snapshot clears its old parent; invalid poll depth is rejected.
    rust_copy_context(ids[0], &rust_task_context, &child);
    expect_context(1, 0);
    threads[1].depth = k_rust_poll_depth + 1;
    assert(!rust_current_context(ids[1]));
    enabled = false;
    assert(!rust_current_context(ids[0]));
    assert(!rust_process_instrumented(ids[0]));
    assert(!rust_tokio_runtime(ids[0]));
    enabled = true;
    capabilities.task_context = 0;
    capabilities.client_context = 0;
    assert(rust_process_instrumented(ids[0]));
    assert(!rust_current_context(ids[0]));
    // Missing task hooks do not make a Tokio worker thread identify a request.
    assert(rust_tokio_runtime(ids[0]));
    capabilities.tokio_runtime = 0;
    assert(!rust_tokio_runtime(ids[0]));
    capabilities.tokio_runtime = 1;
    capabilities.task_context = 1;
    capabilities.client_context = 1;
    run_task(2, 100);
    assert(!rust_current_context(ids[2]));
    run_task(1, 100);
    expect_context(1, 24);
    // The poll probes resolve the same context from the worker state they already hold.
    assert(rust_thread_context(ids[1], &threads[1]) == rust_current_context(ids[1]));

    const rust_http_request_t pending = {.wire = {.span_id = {7}}, .inject = 1};
    rust_save_request(ids[1], &pending);
    assert(rust_current_request(ids[1])->wire.span_id[0] == 7);
    run_task(1, 101);
    assert(!rust_current_request(ids[1]));
    run_task(0, 100);
    assert(rust_current_request(ids[0]));
    rust_observe_request(ids[0]);
    assert(!rust_current_request(ids[0]));
    rust_save_request(ids[0], &pending);
    assert(rust_current_request(ids[0]));

    h2_task = (rust_task_key_t){.pid = pid, .addr = 100};
    h2_key = (rust_h2_key_t){.pid = pid, .sender = h2_sender, .stream_id = 3};
    h2_request = pending;
    assert(rust_current_h2_request(ids[0], 3));
    assert(!rust_current_h2_request(ids[0], 5));
    assert(!rust_current_h2_request(ids[1], 3));
    rust_current_h2_request(ids[0], 3)->observed = 1;
    assert(!rust_current_h2_request(ids[0], 3));
    h2_request = pending;
    // Identical task addresses and stream IDs in another process remain independent.
    run_task(2, 100);
    assert(!rust_current_request(ids[2]));
    assert(!rust_current_h2_request(ids[2], 3));
    assert(rust_current_request(ids[0]));
    assert(rust_current_h2_request(ids[0], 3));

    // Decoded HTTP/2 requests are only handed to the request hook when the reading
    // task, and the socket it saved, can identify their stream there.
    run_task(0, 500);
    assert(!rust_task_has_io_connection(ids[0]));
    const rust_task_key_t reader = {.pid = pid, .addr = 500};
    const ssl_pid_connection_info_t socket = {.orig_dport = 443};
    store(&rust_io_connections, &reader, &socket, 0);
    assert(rust_task_has_io_connection(ids[0]));
    threads[0].depth = 0;
    assert(!rust_task_has_io_connection(ids[0]));

    printf("OK: %s\n", __FILE__);
    return 0;
}
