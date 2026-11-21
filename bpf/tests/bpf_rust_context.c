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
    tp_info_pid_t value;
} entry_t;

static entry_t entries[k_entries];
static bool enabled = true;
static rust_capabilities_t capabilities = {
    .task_context = 1, .client_context = 1, .tokio_runtime = 1};
static rust_thread_state_t threads[3];
static const u64 ids[] = {1ULL << 32 | 1, 1ULL << 32 | 2, 2ULL << 32 | 3};
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
    const u32 size = sizeof(tp_info_pid_t);
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

// trace 0 expects no context: either no entry or a cleared one.
static void expect_context(u32 thread, u8 trace) {
    const tp_info_pid_t *context = rust_current_context(ids[thread]);
    if (!trace) {
        assert(!context || !context->valid);
        return;
    }

    assert(context && context->valid);
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
    rust_inherit_task_context(ids[0], &child);
    run_task(1, child.addr);
    expect_context(1, 42);
    // The spawned copy may outlive its request; the spawner's own context is unchanged.
    assert(rust_current_context(ids[1])->response_sent == 1);
    assert(rust_current_context(ids[0])->response_sent == 0);

    run_task(0, 300);
    // Replacing a task snapshot clears its old parent; invalid poll depth is rejected.
    rust_set_context(ids[1], &parent);
    rust_inherit_task_context(ids[0], &child);
    assert(!lookup(&rust_task_context, &child) && "a recycled task drops its old parent");
    expect_context(1, 0);
    threads[1].depth = k_rust_poll_depth + 1;
    assert(!rust_current_context(ids[1]));
    enabled = false;
    assert(!rust_current_context(ids[0]));
    assert(!rust_process_instrumented(ids[0]));
    assert(!rust_process_capabilities(pid));
    enabled = true;
    capabilities.task_context = 0;
    capabilities.client_context = 0;
    assert(rust_process_instrumented(ids[0]));
    assert(!rust_current_context(ids[0]));
    // Missing task hooks do not make a Tokio worker thread identify a request.
    assert(rust_process_capabilities(pid)->tokio_runtime);
    capabilities.tokio_runtime = 0;
    assert(!rust_process_capabilities(pid)->tokio_runtime);
    capabilities.tokio_runtime = 1;
    capabilities.task_context = 1;
    capabilities.client_context = 1;
    run_task(2, 100);
    assert(!rust_current_context(ids[2]));
    run_task(1, 100);
    expect_context(1, 42);
    // The poll probes resolve the same context from the worker state they already hold.
    assert(rust_thread_context(ids[1], &threads[1]) == rust_current_context(ids[1]));
    printf("OK: %s\n", __FILE__);
    return 0;
}
