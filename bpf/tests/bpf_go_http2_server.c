// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wint-conversion"
#pragma clang diagnostic ignored "-Wint-to-pointer-cast"

#undef BPF_CORE_READ
#define BPF_CORE_READ(src, ...) ((void)(src), 0)

struct pt_regs {
    unsigned long bx;
    unsigned long sp;
};

#define GO_PARAM2(ctx) ((void *)(ctx)->bx)
#define PT_REGS_SP(ctx) ((ctx)->sp)

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline unsigned long long bpf_ktime_get_ns(void) {
    return 0;
}

static inline long bpf_loop(unsigned int nr_loops,
                            int (*callback_fn)(unsigned int, void *),
                            void *callback_ctx,
                            unsigned long long flags) {
    (void)nr_loops;
    (void)callback_fn;
    (void)callback_ctx;
    (void)flags;
    return 0;
}

static void *test_map_lookup(void *map, const void *key);
static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static long test_probe_read(void *dst, unsigned int size, const void *src);
static unsigned long long test_current_pid_tgid(void);
static unsigned long long test_process_start_time(void);

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_probe_read test_probe_read
#define bpf_probe_read_kernel test_probe_read
#define bpf_get_current_pid_tgid test_current_pid_tgid
#define OBI_CURRENT_PROCESS_START_TIME_NS test_process_start_time
#define OBI_CURRENT_PROCESS_START_BOOTTIME_NS test_process_start_time

#include <gotracer/go_common.h>
#include <gotracer/go_http2_server.h>

#undef OBI_CURRENT_PROCESS_START_BOOTTIME_NS
#undef OBI_CURRENT_PROCESS_START_TIME_NS
#undef bpf_get_current_pid_tgid
#undef bpf_probe_read_kernel
#undef bpf_probe_read
#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem
#undef BPF_NOEXIST
#undef BPF_ANY
#undef PT_REGS_SP
#undef GO_PARAM2
#undef BPF_CORE_READ

#pragma clang diagnostic pop

enum { max_test_requests = 4 };
enum { max_test_process_headers_invocations = 3 };

typedef struct request_slot {
    http2_server_stream_key_t key;
    http2_server_request_state_t request;
    u8 present;
} request_slot_t;

typedef struct process_headers_invocation_slot {
    go_exact_process_addr_key_t key;
    http2_process_headers_invocation_t invocation;
    u8 present;
} process_headers_invocation_slot_t;

static unsigned int failures;
static int request_test_map;
static int process_headers_invocation_test_map;
static request_slot_t requests[max_test_requests];
static process_headers_invocation_slot_t
    process_headers_invocations[max_test_process_headers_invocations];
static go_process_generation_t generation = {
    .generation = 7,
    .start_time = 100,
};
static u8 fail_updates;

static int key_equal(const http2_server_stream_key_t *left,
                     const http2_server_stream_key_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static request_slot_t *find_request(const http2_server_stream_key_t *key) {
    for (int i = 0; i < max_test_requests; i++) {
        if (requests[i].present && key_equal(&requests[i].key, key)) {
            return &requests[i];
        }
    }
    return NULL;
}

static process_headers_invocation_slot_t *
find_process_headers_invocation(const go_exact_process_addr_key_t *key) {
    for (int i = 0; i < max_test_process_headers_invocations; i++) {
        if (process_headers_invocations[i].present &&
            memcmp(&process_headers_invocations[i].key, key, sizeof(*key)) == 0) {
            return &process_headers_invocations[i];
        }
    }
    return NULL;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &go_process_generations && *(const u32 *)key == 123) {
        return &generation;
    }
    if (map == &request_test_map) {
        request_slot_t *slot = find_request(key);
        return slot ? &slot->request : NULL;
    }
    if (map == &process_headers_invocation_test_map) {
        process_headers_invocation_slot_t *slot = find_process_headers_invocation(key);
        return slot ? &slot->invocation : NULL;
    }
    return NULL;
}

static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags) {
    if (fail_updates) {
        return -1;
    }
    if (map == &process_headers_invocation_test_map) {
        process_headers_invocation_slot_t *slot = find_process_headers_invocation(key);
        if (!slot) {
            for (int i = 0; i < max_test_process_headers_invocations; i++) {
                if (!process_headers_invocations[i].present) {
                    slot = &process_headers_invocations[i];
                    break;
                }
            }
        }
        if (!slot) {
            return -1;
        }
        slot->key = *(const go_exact_process_addr_key_t *)key;
        slot->invocation = *(const http2_process_headers_invocation_t *)val;
        slot->present = 1;
        return 0;
    }
    if (map != &request_test_map) {
        return -1;
    }
    request_slot_t *slot = find_request(key);
    if (slot && flags == 1) {
        return -1;
    }
    if (!slot) {
        for (int i = 0; i < max_test_requests; i++) {
            if (!requests[i].present) {
                slot = &requests[i];
                break;
            }
        }
    }
    if (!slot) {
        return -1;
    }
    slot->key = *(const http2_server_stream_key_t *)key;
    slot->request = *(const http2_server_request_state_t *)val;
    slot->present = 1;
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &process_headers_invocation_test_map) {
        process_headers_invocation_slot_t *slot = find_process_headers_invocation(key);
        if (!slot) {
            return -1;
        }
        slot->present = 0;
        return 0;
    }
    if (map != &request_test_map) {
        return -1;
    }
    request_slot_t *slot = find_request(key);
    if (!slot) {
        return -1;
    }
    slot->present = 0;
    return 0;
}

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    if (!src) {
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

static unsigned long long test_current_pid_tgid(void) {
    return (unsigned long long)123 << 32;
}

static unsigned long long test_process_start_time(void) {
    return generation.start_time;
}

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_bytes(const void *want, const void *got, size_t len, const char *message) {
    if (memcmp(want, got, len) == 0) {
        return;
    }
    fprintf(stderr, "%s: byte sequences differ\n", message);
    failures++;
}

static tp_info_t test_parent(u8 seed) {
    tp_info_t tp = {
        .flags = 1,
        .parent_remote = 1,
    };
    for (int i = 0; i < TRACE_ID_SIZE_BYTES; i++) {
        tp.trace_id[i] = seed + i;
    }
    for (int i = 0; i < SPAN_ID_SIZE_BYTES; i++) {
        tp.span_id[i] = seed + TRACE_ID_SIZE_BYTES + i;
        tp.parent_id[i] = tp.span_id[i];
    }
    return tp;
}

static http2_server_stream_key_t stream_key(u64 sc, u32 stream_id) {
    return (http2_server_stream_key_t){
        .pid = 123,
        .generation = generation.generation,
        .server_conn = sc,
        .stream_id = stream_id,
    };
}

static void reset_requests(void) {
    memset(requests, 0, sizeof(requests));
    memset(process_headers_invocations, 0, sizeof(process_headers_invocations));
    fail_updates = 0;
}

static void test_process_headers_return_rejects_prior_process_invocation(void) {
    reset_requests();
    const u64 goroutine_addr = 0x7770;
    const go_exact_process_addr_key_t prior_process =
        go_exact_process_addr_key(123, generation.start_time - 1, goroutine_addr);
    const http2_process_headers_invocation_t stale = {
        .stream =
            {
                .pid = 123,
                .generation = generation.generation - 1,
                .server_conn = 0x1110,
                .stream_id = 1,
            },
        .candidate_initial = 1,
    };
    assert_bool(1,
                go_http2_stage_process_headers_invocation(
                    &process_headers_invocation_test_map, &prior_process, &stale),
                "stage invocation from prior PID incarnation");

    go_exact_process_addr_key_t current_process = {};
    assert_bool(1,
                go_http2_process_headers_key(&current_process, (void *)goroutine_addr),
                "build exact current processHeaders key");
    assert_bool(0,
                go_http2_lookup_process_headers_invocation(&process_headers_invocation_test_map,
                                                           &current_process) != NULL,
                "return-only attach cannot consume prior-process invocation");

    go_http2_clear_process_headers_invocation(&process_headers_invocation_test_map,
                                              &current_process);
    assert_bool(1,
                find_process_headers_invocation(&prior_process) != NULL,
                "current-incarnation cleanup cannot alias prior process");

    const http2_process_headers_invocation_t current = {
        .stream =
            {
                .pid = 123,
                .generation = generation.generation,
                .server_conn = 0x2220,
                .stream_id = 3,
            },
        .candidate_initial = 1,
    };
    assert_bool(1,
                go_http2_stage_process_headers_invocation(
                    &process_headers_invocation_test_map, &current_process, &current),
                "stage current process invocation beside stale entry");
    assert_bool(1,
                go_http2_lookup_process_headers_invocation(&process_headers_invocation_test_map,
                                                           &current_process) != NULL,
                "return consumes only current process invocation");
    go_http2_clear_process_headers_invocation(&process_headers_invocation_test_map,
                                              &current_process);
    assert_bool(0,
                go_http2_lookup_process_headers_invocation(&process_headers_invocation_test_map,
                                                           &current_process) != NULL,
                "goroutine reuse cleanup removes current invocation");
    assert_bool(1,
                find_process_headers_invocation(&prior_process) != NULL,
                "current cleanup leaves stale capacity isolated");
}

static void test_multiplexed_streams_are_consumed_exactly(void) {
    reset_requests();
    const http2_server_stream_key_t first_key = stream_key(0x1000, 1);
    const http2_server_stream_key_t second_key = stream_key(0x1000, 3);
    const http2_server_request_state_t first = {
        .tp = test_parent(0x10),
        .traceparent_state = k_go_http1_traceparent_scan_found,
    };
    const http2_server_request_state_t second = {
        .traceparent_state = k_go_http1_traceparent_scan_absent,
    };

    assert_bool(1,
                go_http2_begin_request_state(&request_test_map, &first_key, &first),
                "publish first stream");
    assert_bool(1,
                go_http2_begin_request_state(&request_test_map, &second_key, &second),
                "publish interleaved second stream");

    server_http_func_invocation_t sentinel = {};
    assert_bool(1,
                go_http2_consume_request_state(&request_test_map, &second_key, &sentinel, 1),
                "consume exact second stream");
    assert_bool(k_go_http1_traceparent_scan_absent,
                sentinel.header_traceparent_state,
                "second stream retains explicit absence");
    assert_bool(1, sentinel.is_tls, "second stream retains TLS");
    assert_bool(1, find_request(&first_key) != NULL, "first stream survives second consumption");
    assert_bool(0, find_request(&second_key) != NULL, "second stream is consumed once");

    memset(&sentinel, 0, sizeof(sentinel));
    assert_bool(1,
                go_http2_consume_request_state(&request_test_map, &first_key, &sentinel, 0),
                "consume exact first stream");
    assert_bool(k_go_http1_traceparent_scan_found,
                sentinel.header_traceparent_state,
                "first stream retains found state");
    assert_bytes(&first.tp, &sentinel.tp, sizeof(first.tp), "first stream parent is exact");
}

static void test_trailers_and_rejections_cannot_replace_initial_state(void) {
    reset_requests();
    const http2_server_stream_key_t initial_key = stream_key(0x2000, 5);
    const http2_server_request_state_t initial = {
        .tp = test_parent(0x30),
        .traceparent_state = k_go_http1_traceparent_scan_found,
    };
    const http2_server_request_state_t trailer = {
        .traceparent_state = k_go_http1_traceparent_scan_absent,
    };
    assert_bool(1,
                go_http2_begin_request_state(&request_test_map, &initial_key, &initial),
                "publish provisional initial block");
    assert_bool(0,
                go_http2_initial_header_candidate(initial_key.stream_id, initial_key.stream_id),
                "trailer is not an initial block");
    assert_bool(0,
                go_http2_begin_request_state(&request_test_map, &initial_key, &trailer),
                "NOEXIST prevents later frame replacement");
    assert_bytes(&initial,
                 &find_request(&initial_key)->request,
                 sizeof(initial),
                 "later frame cannot poison initial authority");

    const http2_server_stream_key_t rejected_key = stream_key(0x2000, 7);
    assert_bool(1,
                go_http2_begin_request_state(&request_test_map, &rejected_key, &trailer),
                "rejected initial block is provisional at entry");
    go_http2_finish_request_state(&request_test_map, &rejected_key, 0);
    assert_bool(0, find_request(&rejected_key) != NULL, "rejection consumes no retained capacity");
}

static void test_entry_update_failure_and_wrong_generation_force_root(void) {
    reset_requests();
    const http2_server_stream_key_t key = stream_key(0x3000, 9);
    const http2_server_request_state_t found = {
        .tp = test_parent(0x50),
        .traceparent_state = k_go_http1_traceparent_scan_found,
    };
    fail_updates = 1;
    assert_bool(0,
                go_http2_begin_request_state(&request_test_map, &key, &found),
                "entry update failure is observable");
    go_http2_finish_request_state(&request_test_map, &key, 1);
    fail_updates = 0;

    server_http_func_invocation_t sentinel = {};
    assert_bool(0,
                go_http2_consume_request_state(&request_test_map, &key, &sentinel, 0),
                "missing producer state is not consumed");
    assert_bool(k_go_http1_traceparent_scan_unknown,
                sentinel.header_traceparent_state,
                "missing producer state stays unknown");
    assert_bool(k_go_http_server_parent_force_root,
                go_http_server_parent_authority(NULL, &sentinel, generation.generation),
                "missing producer state forces root");
    assert_bool(generation.generation,
                sentinel.generation,
                "missing producer sentinel records the current process generation");

    http2_server_stream_key_t wrong_generation = key;
    wrong_generation.generation--;
    memset(&sentinel, 0, sizeof(sentinel));
    assert_bool(0,
                go_http2_consume_request_state(&request_test_map, &wrong_generation, &sentinel, 0),
                "generation mismatch is rejected");
    assert_bool(k_go_http1_traceparent_scan_unknown,
                sentinel.header_traceparent_state,
                "generation mismatch stays unknown");
    assert_bool(generation.generation,
                sentinel.generation,
                "generation mismatch sentinel retains the current process generation");
    assert_bool(k_go_http_server_parent_force_root,
                go_http_server_parent_authority(NULL, &sentinel, generation.generation),
                "generation mismatch forces root");
}

static void test_handler_and_return_orderings_do_not_republish(void) {
    reset_requests();
    const http2_server_stream_key_t handler_first_key = stream_key(0x4000, 11);
    const http2_server_request_state_t handler_first = {
        .tp = test_parent(0x60),
        .traceparent_state = k_go_http1_traceparent_scan_found,
    };
    server_http_func_invocation_t sentinel = {};

    assert_bool(1,
                go_http2_begin_request_state(&request_test_map, &handler_first_key, &handler_first),
                "handler-first entry publication");
    assert_bool(1,
                go_http2_consume_request_state(&request_test_map, &handler_first_key, &sentinel, 0),
                "handler consumes before processHeaders return");
    go_http2_finish_request_state(&request_test_map, &handler_first_key, 1);
    assert_bool(0,
                find_request(&handler_first_key) != NULL,
                "accepted return never resurrects consumed state");

    const http2_server_stream_key_t return_first_key = stream_key(0x4000, 13);
    const http2_server_request_state_t return_first = {
        .traceparent_state = k_go_http1_traceparent_scan_absent,
    };
    assert_bool(1,
                go_http2_begin_request_state(&request_test_map, &return_first_key, &return_first),
                "return-first entry publication");
    go_http2_finish_request_state(&request_test_map, &return_first_key, 1);
    assert_bool(1,
                find_request(&return_first_key) != NULL,
                "accepted return retains state for a later handler");
    memset(&sentinel, 0, sizeof(sentinel));
    assert_bool(1,
                go_http2_consume_request_state(&request_test_map, &return_first_key, &sentinel, 0),
                "handler consumes after processHeaders return");
    assert_bool(k_go_http1_traceparent_scan_absent,
                sentinel.header_traceparent_state,
                "return-first ordering preserves explicit absence");
    assert_bool(k_go_http_server_parent_force_root,
                go_http_server_parent_authority(NULL, &sentinel, generation.generation),
                "multiplexed H2 absence cannot use connection-scoped fallback");
}

static void test_h2_header_state_discards_fallback_fail_closed(void) {
    assert_bool(0,
                go_http2_header_requires_parent_discard(k_go_http1_traceparent_scan_absent),
                "proven H2 absence retains connection fallback");
    assert_bool(1,
                go_http2_header_requires_parent_discard(k_go_http1_traceparent_scan_found),
                "valid H2 header discards connection fallback before sentinel publication");
    assert_bool(1,
                go_http2_header_requires_parent_discard(k_go_http1_traceparent_scan_present),
                "invalid H2 header discards connection fallback before sentinel publication");
    assert_bool(1,
                go_http2_header_requires_parent_discard(k_go_http1_traceparent_scan_unknown),
                "ambiguous H2 headers discard connection fallback before sentinel publication");
}

static void test_reset_before_handler_retains_state_and_eviction_forces_root(void) {
    reset_requests();
    const http2_server_stream_key_t reset_key = stream_key(0x5000, 15);
    const http2_server_request_state_t found = {
        .tp = test_parent(0x70),
        .traceparent_state = k_go_http1_traceparent_scan_found,
    };
    server_http_func_invocation_t sentinel = {};

    assert_bool(1,
                go_http2_begin_request_state(&request_test_map, &reset_key, &found),
                "reset case entry publication");
    go_http2_finish_request_state(&request_test_map, &reset_key, 1);
    assert_bool(1,
                find_request(&reset_key) != NULL,
                "stream reset does not revoke state for an already-launched handler");
    assert_bool(1,
                go_http2_consume_request_state(&request_test_map, &reset_key, &sentinel, 0),
                "already-launched handler consumes exact retained state after reset");
    assert_bool(k_go_http1_traceparent_scan_found,
                sentinel.header_traceparent_state,
                "reset before handler preserves exact traceparent authority");
    assert_bool(k_go_http_server_parent_traceparent,
                go_http_server_parent_authority(NULL, &sentinel, generation.generation),
                "retained reset state remains authoritative for the launched handler");
    assert_bytes(&found.tp, &sentinel.tp, sizeof(found.tp), "reset state keeps the exact parent");

    const http2_server_stream_key_t evicted_key = stream_key(0x5000, 17);
    assert_bool(1,
                go_http2_begin_request_state(&request_test_map, &evicted_key, &found),
                "eviction case entry publication");
    find_request(&evicted_key)->present = 0;
    go_http2_finish_request_state(&request_test_map, &evicted_key, 1);
    memset(&sentinel, 0, sizeof(sentinel));
    assert_bool(0,
                go_http2_consume_request_state(&request_test_map, &evicted_key, &sentinel, 0),
                "accepted return does not recreate evicted state");
    assert_bool(k_go_http1_traceparent_scan_unknown,
                sentinel.header_traceparent_state,
                "eviction before handler forces root");
    assert_bool(k_go_http_server_parent_force_root,
                go_http_server_parent_authority(NULL, &sentinel, generation.generation),
                "evicted stream state cannot fall back to connection correlation");
}

int main(void) {
    test_process_headers_return_rejects_prior_process_invocation();
    test_multiplexed_streams_are_consumed_exactly();
    test_trailers_and_rejections_cannot_replace_initial_state();
    test_entry_update_failure_and_wrong_generation_force_root();
    test_handler_and_return_orderings_do_not_republish();
    test_h2_header_state_discards_fallback_fail_closed();
    test_reset_before_handler_retains_state_and_eviction_forces_root();
    return failures == 0 ? 0 : 1;
}
