// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

enum { k_max_maps = 8, k_max_entries = 16, k_max_key = 16, k_max_val = 1024 };

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

#include <gotracer/grpc_client_stack.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem

static const go_addr_key_t g_key = {.pid = 0x10, .addr = 0x2000};
static int failures;

static void check(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static void check_u64(u64 expected, u64 actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr,
                "FAIL: %s (expected %llu, got %llu)\n",
                message,
                (unsigned long long)expected,
                (unsigned long long)actual);
        failures++;
    }
}

static void test_lifo_basic(void) {
    grpc_client_invocation_stack_t stack = {0};
    mock_register(&ongoing_grpc_client_requests,
                  sizeof(go_addr_key_t),
                  sizeof(grpc_client_invocation_stack_t));

    grpc_client_func_invocation_t invA = {.cc = 0x111, .stack_off = 100};
    grpc_client_func_invocation_t invB = {.cc = 0x222, .stack_off = 200};

    // Push A
    check(grpc_client_push(&g_key, &stack, &invA), "push A succeeds");
    test_map_update(&ongoing_grpc_client_requests, &g_key, &stack, 0);
    check_u64(1, grpc_client_depth(&stack), "depth after push A is 1");
    grpc_client_func_invocation_t *cur = grpc_client_current(&stack);
    check(cur != NULL && cur->cc == 0x111, "current is A");

    // Push B
    check(grpc_client_push(&g_key, &stack, &invB), "push B succeeds");
    test_map_update(&ongoing_grpc_client_requests, &g_key, &stack, 0);
    check_u64(2, grpc_client_depth(&stack), "depth after push B is 2");
    cur = grpc_client_current(&stack);
    check(cur != NULL && cur->cc == 0x222, "current is B");

    // Pop B
    grpc_client_func_invocation_t popped = {0};
    check(grpc_client_pop(&g_key, &stack, &popped), "pop B succeeds");
    test_map_update(&ongoing_grpc_client_requests, &g_key, &stack, 0);
    check_u64(0x222, popped.cc, "popped item is B");
    check_u64(1, grpc_client_depth(&stack), "depth after pop B is 1");
    cur = grpc_client_current(&stack);
    check(cur != NULL && cur->cc == 0x111, "current restored to A");

    // Pop A
    check(grpc_client_pop(&g_key, &stack, &popped), "pop A succeeds");
    check_u64(0x111, popped.cc, "popped item is A");
    check_u64(0, grpc_client_depth(&stack), "depth after pop A is 0");
    check(grpc_client_current(&stack) == NULL, "current is NULL when empty");
    check(test_map_lookup(&ongoing_grpc_client_requests, &g_key) == NULL,
          "map entry deleted when depth is 0");
}

static void test_stack_growth_restart(void) {
    grpc_client_invocation_stack_t stack = {0};

    grpc_client_func_invocation_t inv1 = {.cc = 0x111, .stack_off = 100, .method = 0xAAA};
    check(grpc_client_push(&g_key, &stack, &inv1), "push 1 succeeds");
    check_u64(1, grpc_client_depth(&stack), "depth is 1");

    // Function restarted by Go runtime at same stack depth
    grpc_client_func_invocation_t inv1_restart = {.cc = 0x111, .stack_off = 100, .method = 0xBBB};
    check(grpc_client_push(&g_key, &stack, &inv1_restart),
          "restart at same stack_off returns true");
    check_u64(1, grpc_client_depth(&stack), "depth does not increase on restart");

    grpc_client_func_invocation_t *cur = grpc_client_current(&stack);
    check(cur != NULL && cur->method == 0xBBB, "restarted frame data was updated");

    grpc_client_func_invocation_t popped = {0};
    check(grpc_client_pop(&g_key, &stack, &popped), "pop succeeds");
    check_u64(0, grpc_client_depth(&stack), "depth is 0");
}

static void test_overflow(void) {
    grpc_client_invocation_stack_t stack = {0};

    for (u64 i = 1; i <= 4; i++) {
        grpc_client_func_invocation_t inv = {.cc = i, .stack_off = (u32)(i * 100)};
        check(grpc_client_push(&g_key, &stack, &inv), "push within bounds succeeds");
        check_u64(i, grpc_client_depth(&stack), "depth matches");
    }
    check_u64(0, stack.overflow, "overflow is 0");
    grpc_client_func_invocation_t *cur = grpc_client_current(&stack);
    check(cur != NULL && cur->cc == 4, "current is frame 4");

    // Push 5th (overflow)
    grpc_client_func_invocation_t inv5 = {.cc = 5, .stack_off = 500};
    check(!grpc_client_push(&g_key, &stack, &inv5), "push 5th reports untracked/overflow");
    check_u64(4, grpc_client_depth(&stack), "depth clamped at max 4");
    check_u64(1, stack.overflow, "overflow is 1");
    check(grpc_client_current(&stack) == NULL, "current must be NULL during overflow, not frame 4");

    // Push 5th restart (same stack_off in overflow)
    grpc_client_func_invocation_t inv5_restart = {.cc = 55, .stack_off = 500};
    check(!grpc_client_push(&g_key, &stack, &inv5_restart),
          "restart in overflow reports untracked");
    check_u64(1, stack.overflow, "overflow does not increment on restart");

    // Push 6th
    grpc_client_func_invocation_t inv6 = {.cc = 6, .stack_off = 600};
    check(!grpc_client_push(&g_key, &stack, &inv6), "push 6th reports untracked/overflow");
    check_u64(2, stack.overflow, "overflow is 2");
    check(grpc_client_current(&stack) == NULL, "current remains NULL");

    // Pop 6th return
    grpc_client_func_invocation_t popped = {0};
    check(!grpc_client_pop(&g_key, &stack, &popped), "pop of 6th returns false (untracked)");
    check_u64(1, stack.overflow, "overflow is 1");
    check(grpc_client_current(&stack) == NULL, "current remains NULL");

    // Pop 5th return
    check(!grpc_client_pop(&g_key, &stack, &popped), "pop of 5th returns false (untracked)");
    check_u64(0, stack.overflow, "overflow returns to 0");
    cur = grpc_client_current(&stack);
    check(cur != NULL && cur->cc == 4, "deepest tracked frame 4 becomes visible again");

    // Pop 4, 3, 2, 1
    for (u64 i = 4; i >= 1; i--) {
        check(grpc_client_pop(&g_key, &stack, &popped), "pop tracked frame succeeds");
        check_u64(i, popped.cc, "popped frame matches");
    }
    check_u64(0, grpc_client_depth(&stack), "stack empty");
}

static void test_stream_pointer_reuse(void) {
    mock_register(&completed_grpc_client_streams, sizeof(go_addr_key_t), sizeof(u8));
    mock_register(
        &early_grpc_client_finishes, sizeof(go_addr_key_t), sizeof(grpc_client_early_finish_t));
    mock_register(
        &ongoing_grpc_client_streams, sizeof(go_addr_key_t), sizeof(grpc_client_stream_state_t));
    mock_register(
        &tracked_grpc_client_streams, sizeof(go_addr_key_t), sizeof(u8));

    const go_addr_key_t stream_key = {.pid = 0x42, .addr = 0x5000};
    u8 dummy = 1;
    grpc_client_early_finish_t early = {.has_err = 0};
    grpc_client_stream_state_t ongoing = {0};

    // 1. Generation A finishes: marked in completed_grpc_client_streams
    test_map_update(&completed_grpc_client_streams, &stream_key, &dummy, 0);
    check(test_map_lookup(&completed_grpc_client_streams, &stream_key) != NULL,
          "generation A marked completed");

    // Also simulate stale early or ongoing residue
    test_map_update(&early_grpc_client_finishes, &stream_key, &early, 0);
    test_map_update(&ongoing_grpc_client_streams, &stream_key, &ongoing, 0);

    // 2. Go allocator reuses address for Generation B:
    // Construction hook (withRetry) establishes fresh generation for stream_key
    grpc_client_begin_stream_generation(&stream_key);

    // 3. Verify that stale completed tombstone, early finish, and ongoing state are cleared
    check(test_map_lookup(&completed_grpc_client_streams, &stream_key) == NULL,
          "stale completed tombstone invalidated by new stream generation");
    check(test_map_lookup(&early_grpc_client_finishes, &stream_key) == NULL,
          "stale early finish marker invalidated by new stream generation");
    check(test_map_lookup(&ongoing_grpc_client_streams, &stream_key) == NULL,
          "stale ongoing stream state invalidated by new stream generation");

    // 4. Generation B early finish can now register without being suppressed by generation A tombstone
    test_map_update(&early_grpc_client_finishes, &stream_key, &early, 0);
    check(test_map_lookup(&early_grpc_client_finishes, &stream_key) != NULL,
          "generation B early finish marker successfully registered");

    // Cleanup
    test_map_delete(&early_grpc_client_finishes, &stream_key);
    test_map_delete(&tracked_grpc_client_streams, &stream_key);
}

static void test_constructor_lifecycle_helpers(void) {
    grpc_client_invocation_stack_t stack = {0};

    go_addr_key_t g_key = {.pid = 0x42, .addr = 0x9000};
    mock_register(&ongoing_grpc_client_requests,
                  sizeof(go_addr_key_t),
                  sizeof(grpc_client_invocation_stack_t));

    // Null safety
    grpc_client_constructor_begin(NULL);
    grpc_client_constructor_end(NULL);

    // Frame 0: Stream A
    grpc_client_func_invocation_t inv_a = {
        .cc = 0x100,
        .stack_off = 100,
        .func_type = k_grpc_client_func_type_new_stream,
        .stream_constructor_active = 0,
    };
    check(grpc_client_push(&g_key, &stack, &inv_a), "push inv_a");
    grpc_client_func_invocation_t *cur_a = grpc_client_current(&stack);
    check(cur_a != NULL, "cur_a not null");
    check_u64(0, cur_a->stream_constructor_active, "inv_a constructor not active initially");

    // Begin constructor on Stream A
    grpc_client_constructor_begin(cur_a);
    check_u64(1, cur_a->stream_constructor_active, "inv_a constructor active after begin");

    // Nested Frame 1: Stream B started inside an interceptor
    grpc_client_func_invocation_t inv_b = {
        .cc = 0x200,
        .stack_off = 200,
        .func_type = k_grpc_client_func_type_new_stream,
        .stream_constructor_active = 0,
    };
    check(grpc_client_push(&g_key, &stack, &inv_b), "push inv_b");
    grpc_client_func_invocation_t *cur_b = grpc_client_current(&stack);
    check(cur_b != NULL, "cur_b not null");
    check_u64(0, cur_b->stream_constructor_active, "inv_b constructor initially inactive");

    // Begin constructor on Stream B
    grpc_client_constructor_begin(cur_b);
    check_u64(1, cur_b->stream_constructor_active, "inv_b constructor active after begin");

    // End constructor on Stream B
    grpc_client_constructor_end(cur_b);
    check_u64(0, cur_b->stream_constructor_active, "inv_b constructor inactive after end");

    // Pop Stream B
    grpc_client_func_invocation_t popped_b;
    check(grpc_client_pop(&g_key, &stack, &popped_b), "pop inv_b");
    check_u64(0x200, popped_b.cc, "popped inv_b matches");

    // Current is now Stream A again; its constructor status is untouched
    cur_a = grpc_client_current(&stack);
    check(cur_a != NULL, "cur_a not null after popping b");
    check_u64(0x100, cur_a->cc, "current is inv_a");
    check_u64(1, cur_a->stream_constructor_active, "inv_a constructor remains active");

    // End constructor on Stream A
    grpc_client_constructor_end(cur_a);
    check_u64(0, cur_a->stream_constructor_active, "inv_a constructor inactive after end");

    grpc_client_func_invocation_t popped_a;
    check(grpc_client_pop(&g_key, &stack, &popped_a), "pop inv_a");
    check_u64(0x100, popped_a.cc, "popped inv_a matches");
    check_u64(0, grpc_client_depth(&stack), "stack empty");
}

int main(void) {
    test_lifo_basic();
    test_stack_growth_restart();
    test_overflow();
    test_stream_pointer_reuse();
    test_constructor_lifecycle_helpers();

    if (failures == 0) {
        printf("test_grpc_client_stack: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_grpc_client_stack: %d check(s) failed\n", failures);
    return 1;
}
