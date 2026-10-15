// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Python asyncio task steps: what the thread's traces_ctx_v1 entry points at while steps start,
// nest (an eager child task running inside its parent's step) and return.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif

enum { k_max_maps = 4, k_max_entries = 16, k_max_key = 32, k_max_val = 128 };

typedef struct mock_entry {
    int used;
    unsigned char key[k_max_key];
    unsigned char val[k_max_val];
} mock_entry_t;

typedef struct mock_map {
    void *map;
    unsigned int key_size;
    unsigned int val_size;
    mock_entry_t entries[k_max_entries];
} mock_map_t;

static mock_map_t mock_maps[k_max_maps];

static mock_map_t *mock_for(void *map) {
    for (int i = 0; i < k_max_maps; i++) {
        if (mock_maps[i].map == map) {
            return &mock_maps[i];
        }
    }
    fprintf(stderr, "FAIL: unregistered map %p\n", map);
    exit(1);
}

static void mock_register(void *map, unsigned int key_size, unsigned int val_size) {
    if (key_size > k_max_key || val_size > k_max_val) {
        fprintf(stderr, "FAIL: mock map too small (key %u, val %u)\n", key_size, val_size);
        exit(1);
    }
    for (int i = 0; i < k_max_maps; i++) {
        if (!mock_maps[i].map) {
            mock_maps[i].map = map;
            mock_maps[i].key_size = key_size;
            mock_maps[i].val_size = val_size;
            return;
        }
    }
    exit(1);
}

static void *test_map_lookup(void *map, const void *key) {
    mock_map_t *m = mock_for(map);
    for (int i = 0; i < k_max_entries; i++) {
        if (m->entries[i].used && memcmp(m->entries[i].key, key, m->key_size) == 0) {
            return m->entries[i].val;
        }
    }
    return NULL;
}

static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags) {
    (void)flags;
    mock_map_t *m = mock_for(map);
    for (int i = 0; i < k_max_entries; i++) {
        if (m->entries[i].used && memcmp(m->entries[i].key, key, m->key_size) == 0) {
            memcpy(m->entries[i].val, val, m->val_size);
            return 0;
        }
    }
    for (int i = 0; i < k_max_entries; i++) {
        if (!m->entries[i].used) {
            m->entries[i].used = 1;
            memcpy(m->entries[i].key, key, m->key_size);
            memcpy(m->entries[i].val, val, m->val_size);
            return 0;
        }
    }
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    mock_map_t *m = mock_for(map);
    for (int i = 0; i < k_max_entries; i++) {
        if (m->entries[i].used && memcmp(m->entries[i].key, key, m->key_size) == 0) {
            m->entries[i].used = 0;
            return 0;
        }
    }
    return -1;
}

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete

#include <common/python_task_step.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem

enum { k_pid = 0x2a, k_thread = ((u64)k_pid << 32) | 0x42 };

enum {
    k_parent = 0x1000,
    k_child = 0x2000,
    k_grandchild = 0x3000,
};

static int failures;

static void check_u64(u64 expected, u64 actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr,
                "FAIL: %s\n  expected %llu, got %llu\n",
                message,
                (unsigned long long)expected,
                (unsigned long long)actual);
        failures++;
    }
}

static python_thread_state_t thread_state;

// span id the thread's logs and profile samples would be attributed to; 0 when there is none
static u64 thread_span(void) {
    const u64 key = k_thread;
    const obi_ctx_info_t *ctx = test_map_lookup(&traces_ctx_v1, &key);
    u64 id = 0;
    if (ctx) {
        memcpy(&id, ctx->span_id, sizeof(id));
    }
    return id;
}

// A task owning a server request on its own connection (port), whose span id is span.
static void task_with_request(u64 task, u16 port, u64 span) {
    connection_info_part_t conn = {0};
    conn.pid = k_pid;
    conn.port = port;
    conn.type = 1;

    const python_addr_key_t key = python_addr_key(k_thread, task);
    python_task_state_t state = {0};
    state.generation = task;
    state.conn = conn;
    test_map_update(&python_task_state, &key, &state, BPF_ANY);

    tp_info_pid_t tp = {0};
    memset(tp.tp.trace_id, 0xab, sizeof(tp.tp.trace_id));
    memcpy(tp.tp.span_id, &span, sizeof(span));
    tp.valid = 1;
    test_map_update(&server_traces_aux, &conn, &tp, BPF_ANY);
}

static void reset(void) {
    for (int i = 0; i < k_max_maps; i++) {
        for (int e = 0; e < k_max_entries; e++) {
            mock_maps[i].entries[e].used = 0;
        }
    }
    memset(&thread_state, 0, sizeof(thread_state));
    bpf_current_pid_tgid_value = k_thread;

    task_with_request(k_parent, 1001, 1);
    task_with_request(k_child, 1002, 2);
    task_with_request(k_grandchild, 1003, 3);
}

static void enter(u64 task) {
    python_task_step_enter(k_thread, &thread_state, task);
}

static void leave(void) {
    python_task_step_exit(k_thread, &thread_state);
}

static void test_step_sets_and_clears(void) {
    reset();
    enter(k_parent);
    check_u64(1, thread_span(), "a step sets its request's context");
    leave();
    check_u64(0, thread_span(), "returning to the event loop clears it");
    check_u64(k_python_state_none, thread_state.current_task, "no task is current in the loop");
}

static void test_eager_child_restores_parent(void) {
    reset();
    enter(k_parent);
    // the parent creates an eager child: its first step runs right away, inside the parent's
    enter(k_child);
    check_u64(2, thread_span(), "the eager child's step runs under its own request");
    check_u64(1, thread_state.outer_depth, "the parent is kept while the child runs");
    leave();
    check_u64(1, thread_span(), "the parent logs right after: its context is back");
    check_u64(k_parent, thread_state.current_task, "the parent is current again");
    check_u64(0, thread_state.outer_depth, "nothing is left kept");
    leave();
    check_u64(0, thread_span(), "the parent's own return clears the context");
}

static void test_same_task_nesting_is_one_level(void) {
    reset();
    // task_step calls task_step_impl for the same task: both are probed
    enter(k_parent);
    enter(k_parent);
    check_u64(0, thread_state.outer_depth, "the same task is not kept under itself");
    check_u64(1, thread_span(), "the task's context is set");
    leave();
    check_u64(0, thread_span(), "task_step_impl's return clears it");
    leave();
    check_u64(0, thread_span(), "task_step's return keeps it cleared");
}

static void test_eager_child_inside_task_step(void) {
    reset();
    // parent stepped through task_step -> task_step_impl, eager child via task_step_impl only
    enter(k_parent);
    enter(k_parent);
    enter(k_child);
    leave();
    check_u64(1, thread_span(), "the parent's context is back after the child");
    leave();
    leave();
    check_u64(0, thread_span(), "both parent returns end at the event loop");
}

static void test_nested_eager_children(void) {
    reset();
    enter(k_parent);
    enter(k_child);
    enter(k_grandchild);
    check_u64(3, thread_span(), "the innermost eager step is current");
    check_u64(2, thread_state.outer_depth, "both enclosing tasks are kept");
    leave();
    check_u64(2, thread_span(), "the child is back after the grandchild");
    leave();
    check_u64(1, thread_span(), "the parent is back after the child");
    leave();
    check_u64(0, thread_span(), "and the loop after the parent");
}

static void test_loop_step_drops_stale_levels(void) {
    reset();
    enter(k_parent);
    enter(k_child);
    // the child's and the parent's returns were missed; the loop clears the current task
    thread_state.current_task = k_python_state_none;
    obi_ctx__del(k_thread);

    enter(k_grandchild);
    check_u64(0, thread_state.outer_depth, "a step from the loop drops stale kept tasks");
    leave();
    check_u64(0, thread_span(), "its return goes back to the loop, not to a stale task");
}

static void test_overflow_keeps_stored_levels(void) {
    reset();
    enum { k_extra = 0x9000 };
    task_with_request(k_extra, 1009, 9);

    enter(k_parent);
    enter(k_child);
    enter(k_grandchild);
    enter(k_child);
    enter(k_grandchild);
    check_u64(k_python_outer_tasks_max, thread_state.outer_depth, "all slots are used");
    enter(k_extra);
    check_u64(1, thread_state.outer_overflow, "a level too deep is counted, not stored");
    check_u64(9, thread_span(), "the too-deep step still runs under its request");

    leave();
    check_u64(0, thread_state.outer_overflow, "its return consumes the count");
    check_u64(0, thread_span(), "its enclosing task is unknown");
    check_u64(k_python_outer_tasks_max, thread_state.outer_depth, "stored levels are intact");

    leave();
    check_u64(2, thread_span(), "the stored levels unwind afterwards");
    leave();
    leave();
    leave();
    check_u64(1, thread_span(), "down to the parent");
    leave();
    check_u64(0, thread_span(), "and the loop");
}

static void test_disabled_map_is_untouched(void) {
    reset();
    g_traces_ctx_v1_enabled = false;
    enter(k_parent);
    enter(k_child);
    leave();
    check_u64(0, thread_span(), "nothing is written without a reader");
    check_u64(k_parent, thread_state.current_task, "the task tracking still unwinds");
    g_traces_ctx_v1_enabled = true;
}

int main(void) {
    mock_register(&python_task_state, sizeof(python_addr_key_t), sizeof(python_task_state_t));
    mock_register(&server_traces_aux, sizeof(connection_info_part_t), sizeof(tp_info_pid_t));
    mock_register(&traces_ctx_v1, sizeof(u64), sizeof(obi_ctx_info_t));
    g_traces_ctx_v1_enabled = true;

    test_step_sets_and_clears();
    test_eager_child_restores_parent();
    test_same_task_nesting_is_one_level();
    test_eager_child_inside_task_step();
    test_nested_eager_children();
    test_loop_step_drops_stale_levels();
    test_overflow_keeps_stored_levels();
    test_disabled_map_is_untouched();

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("bpf_python_task_step: all tests passed\n");
    return 0;
}
