// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Per-goroutine context stack: what the thread's traces_ctx_v1 entry points at
// while spans begin, restart, nest, overflow and end.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif

enum { BPF_ANY = 0 };

struct pt_regs {
    u64 sp;
};

static unsigned char test_g[16];
static u64 test_stack_hi;

#define GOROUTINE_PTR(x) ((void *)test_g)
#define PT_REGS_SP(x) ((x)->sp)

enum { k_max_maps = 4, k_max_entries = 16, k_max_key = 16, k_max_val = 512 };

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

// the only user read is g.stack.hi
static long test_probe_read_user(void *dst, unsigned int size, const void *src) {
    (void)src;
    memcpy(dst, &test_stack_hi, size);
    return 0;
}

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_probe_read_user test_probe_read_user

#include <gotracer/go_obi_ctx.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem
#undef bpf_probe_read_user

enum { k_thread = 0x0000002a00000042ULL };

static const go_addr_key_t g_key = {.pid = 0x2a, .addr = 0x1000};
static const go_addr_key_t other_g_key = {.pid = 0x2a, .addr = 0x2000};

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
                "FAIL: %s\n  expected %llu, got %llu\n",
                message,
                (unsigned long long)expected,
                (unsigned long long)actual);
        failures++;
    }
}

static tp_info_t span(u64 id) {
    tp_info_t tp = {0};
    memset(tp.trace_id, 0xab, sizeof(tp.trace_id));
    memcpy(tp.span_id, &id, sizeof(id));
    return tp;
}

// span id the thread's logs would be attributed to; 0 when there is none
static u64 thread_span(void) {
    const u64 key = k_thread;
    const obi_ctx_info_t *ctx = test_map_lookup(&traces_ctx_v1, &key);
    u64 id = 0;
    if (ctx) {
        memcpy(&id, ctx->span_id, sizeof(id));
    }
    return id;
}

static obi_ctx_stack_t *stack(void) {
    return test_map_lookup(&obi_ctx_stacks, &g_key);
}

static void begin(u8 kind, tp_info_t tp, u32 stack_off) {
    go_obi_ctx__begin(&g_key, kind, &tp, stack_off);
}

static void end(u8 kind, tp_info_t tp) {
    go_obi_ctx__end(&g_key, kind, &tp);
}

static void end_unknown(u8 kind) {
    go_obi_ctx__end(&g_key, kind, NULL);
}

static void reset(void) {
    for (int i = 0; i < k_max_maps; i++) {
        for (int e = 0; e < k_max_entries; e++) {
            mock_maps[i].entries[e].used = 0;
        }
    }
    // the per-cpu scratch slot always exists
    const u32 zero = 0;
    const obi_ctx_stack_t empty = {0};
    test_map_update(&obi_ctx_stack_scratch_storage, &zero, &empty, 0);
    bpf_current_pid_tgid_value = k_thread;
}

static void test_begin_end_nesting(void) {
    reset();
    begin(k_obi_ctx_http_server, span(1), 100);
    check_u64(1, thread_span(), "server begin sets the thread context");
    begin(k_obi_ctx_sql, span(2), 200);
    check_u64(2, thread_span(), "nested client begin takes over");
    check_u64(2, stack()->depth, "nested client is a second frame");

    end(k_obi_ctx_sql, span(2));
    check_u64(1, thread_span(), "client end restores the server span");
    end(k_obi_ctx_http_server, span(1));
    check(stack() == NULL, "last end drops the stack");
    check_u64(0, thread_span(), "last end clears the thread context");
}

static void test_stack_growth_restart_refreshes_frame(void) {
    reset();
    begin(k_obi_ctx_kafka_produce, span(3), 300);
    // Go grew the stack and restarted the function: same depth, new span id
    begin(k_obi_ctx_kafka_produce, span(4), 300);
    check_u64(1, stack()->depth, "restart does not add a frame");
    check_u64(4, thread_span(), "restart updates the span");

    end(k_obi_ctx_kafka_produce, span(4));
    check(stack() == NULL, "one end closes the restarted span");
    check_u64(0, thread_span(), "nothing stale is left on the thread");
}

static void test_same_kind_nesting_keeps_both(void) {
    reset();
    begin(k_obi_ctx_http_server, span(5), 100);
    begin(k_obi_ctx_sql, span(6), 200);
    begin(k_obi_ctx_sql, span(7), 260);
    check_u64(3, stack()->depth, "a deeper same-kind call is a new frame");

    end(k_obi_ctx_sql, span(7));
    check_u64(6, thread_span(), "inner end restores the outer SQL span");
    // the inner query overwrote the outer one's map entry: its end has no tp
    end_unknown(k_obi_ctx_sql);
    check_u64(5, thread_span(), "outer end by kind restores the server span");
}

static void test_server_begin_replaces_and_unwinds(void) {
    reset();
    begin(k_obi_ctx_http_server, span(8), 100);
    begin(k_obi_ctx_sql, span(9), 200);
    // the SQL return was never seen; a new request starts on this goroutine
    begin(k_obi_ctx_http_server, span(10), 100);
    check_u64(1, stack()->depth, "new request drops the stale client frame");
    check_u64(10, thread_span(), "new request owns the thread context");

    go_obi_ctx__resume(k_thread, &g_key);
    check_u64(10, thread_span(), "rescheduling keeps the new request");
}

static void test_overflow_counts_each_span_once(void) {
    reset();
    begin(k_obi_ctx_http_server, span(11), 100);
    begin(k_obi_ctx_sql, span(12), 210);
    begin(k_obi_ctx_sql, span(13), 220);
    begin(k_obi_ctx_sql, span(14), 230);
    check_u64(k_obi_ctx_max_depth, stack()->depth, "stack is full");

    begin(k_obi_ctx_sql, span(15), 240);
    check_u64(1, stack()->overflow, "fifth span is counted, not stored");
    check_u64(15, thread_span(), "unstored span is still the current one");
    // stack growth restart of the unstored span
    begin(k_obi_ctx_sql, span(16), 240);
    check_u64(1, stack()->overflow, "restart of an unstored span is not counted again");
    begin(k_obi_ctx_sql, span(17), 250);
    check_u64(2, stack()->overflow, "a deeper unstored span is counted");

    end(k_obi_ctx_sql, span(17));
    check_u64(1, stack()->overflow, "unknown end while overflowed consumes one count");
    check_u64(14, thread_span(), "and falls back to the deepest stored span");
    end_unknown(k_obi_ctx_sql);
    check_u64(0, stack()->overflow, "end without tp also consumes the count");
    check_u64(k_obi_ctx_max_depth, stack()->depth, "and does not pop a stored frame");

    end(k_obi_ctx_sql, span(14));
    check_u64(13, thread_span(), "stored spans unwind normally afterwards");
    end_unknown(k_obi_ctx_sql);
    check_u64(12, thread_span(), "end by kind pops the newest SQL frame");
    end(k_obi_ctx_sql, span(12));
    end(k_obi_ctx_http_server, span(11));
    check(stack() == NULL, "stack is gone once everything ended");
}

static void test_sibling_after_unstored_end_is_counted(void) {
    reset();
    begin(k_obi_ctx_http_server, span(18), 100);
    begin(k_obi_ctx_sql, span(19), 210);
    begin(k_obi_ctx_sql, span(20), 220);
    begin(k_obi_ctx_sql, span(21), 230);
    begin(k_obi_ctx_sql, span(22), 240);
    begin(k_obi_ctx_sql, span(23), 250);
    check_u64(2, stack()->overflow, "two unstored spans");

    end(k_obi_ctx_sql, span(23));
    // a second query at the same depth as the one that just ended
    begin(k_obi_ctx_sql, span(24), 250);
    check_u64(2, stack()->overflow, "a sibling after an end is a new span");
    end(k_obi_ctx_sql, span(24));
    end(k_obi_ctx_sql, span(22));
    check_u64(0, stack()->overflow, "all unstored spans ended");
    check_u64(k_obi_ctx_max_depth, stack()->depth, "no stored frame was popped");
}

static void test_unknown_end_without_overflow_is_a_noop(void) {
    reset();
    begin(k_obi_ctx_http_server, span(25), 100);
    // e.g. ClientConn.Close on a goroutine with no gRPC client span
    end_unknown(k_obi_ctx_grpc_client);
    check_u64(1, stack()->depth, "nothing was popped");
    check_u64(25, thread_span(), "the server span stays current");
}

static void test_resume(void) {
    reset();
    begin(k_obi_ctx_http_server, span(26), 100);
    obi_ctx__del(k_thread);
    go_obi_ctx__resume(k_thread, &g_key);
    check_u64(26, thread_span(), "resume reinstalls the goroutine's span");

    go_obi_ctx__resume(k_thread, &other_g_key);
    check_u64(0, thread_span(), "a goroutine without spans clears the thread");
}

static void test_stack_off(void) {
    struct pt_regs regs = {.sp = 0x7000};
    test_stack_hi = 0x7400;
    check_u64(0x400, go_obi_ctx__stack_off(&regs), "stack_off is the used stack size");
}

int main(void) {
    mock_register(&obi_ctx_stacks, sizeof(go_addr_key_t), sizeof(obi_ctx_stack_t));
    mock_register(&traces_ctx_v1, sizeof(u64), sizeof(obi_ctx_info_t));
    mock_register(&obi_ctx_stack_scratch_storage, sizeof(u32), sizeof(obi_ctx_stack_t));

    test_begin_end_nesting();
    test_stack_growth_restart_refreshes_frame();
    test_same_kind_nesting_keeps_both();
    test_server_begin_replaces_and_unwinds();
    test_overflow_counts_each_span_once();
    test_sibling_after_unstored_end_is_counted();
    test_unknown_end_without_overflow_is_a_noop();
    test_resume();
    test_stack_off();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("bpf_go_obi_ctx: all checks passed\n");
    return 0;
}
