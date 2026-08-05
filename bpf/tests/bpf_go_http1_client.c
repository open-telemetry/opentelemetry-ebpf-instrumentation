// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static void *test_map_lookup(void *map, const void *key);
static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static long test_map_delete(void *map, const void *key);

#define BPF_ANY 0
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete

#include <gotracer/go_http1_client.h>

#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem
#undef BPF_ANY

enum { k_locator_capacity = 4 };

typedef struct locator_entry {
    http1_header_request_key_t key;
    go_exact_process_addr_key_t request;
    u8 present;
} locator_entry_t;

static int locator_map;
static int writer_map;
static locator_entry_t locators[k_locator_capacity];
static go_exact_process_addr_key_t writer_key;
static u8 writer_present;
static unsigned int failures;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_exact(const go_exact_process_addr_key_t *want,
                         const go_exact_process_addr_key_t *got,
                         const char *message) {
    assert_bool(1, memcmp(want, got, sizeof(*want)) == 0, message);
}

static void reset_maps(void) {
    memset(locators, 0, sizeof(locators));
    memset(&writer_key, 0, sizeof(writer_key));
    writer_present = 0;
}

static u8 locator_count(void) {
    u8 count = 0;
    for (u8 i = 0; i < k_locator_capacity; i++) {
        count += locators[i].present;
    }
    return count;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map != &locator_map) {
        return 0;
    }
    for (u8 i = 0; i < k_locator_capacity; i++) {
        if (locators[i].present && memcmp(key, &locators[i].key, sizeof(locators[i].key)) == 0) {
            return &locators[i].request;
        }
    }
    return 0;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    (void)flags;
    if (map != &locator_map) {
        return -1;
    }
    for (u8 i = 0; i < k_locator_capacity; i++) {
        if (locators[i].present && memcmp(key, &locators[i].key, sizeof(locators[i].key)) == 0) {
            locators[i].request = *(const go_exact_process_addr_key_t *)value;
            return 0;
        }
    }
    for (u8 i = 0; i < k_locator_capacity; i++) {
        if (!locators[i].present) {
            locators[i].key = *(const http1_header_request_key_t *)key;
            locators[i].request = *(const go_exact_process_addr_key_t *)value;
            locators[i].present = 1;
            return 0;
        }
    }
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &locator_map) {
        for (u8 i = 0; i < k_locator_capacity; i++) {
            if (locators[i].present &&
                memcmp(key, &locators[i].key, sizeof(locators[i].key)) == 0) {
                locators[i].present = 0;
                return 0;
            }
        }
        return -1;
    }
    if (map == &writer_map && writer_present && memcmp(key, &writer_key, sizeof(writer_key)) == 0) {
        writer_present = 0;
        return 0;
    }
    return -1;
}

static void test_shared_header_is_connection_scoped(void) {
    reset_maps();
    const go_exact_process_addr_key_t request_a = go_exact_process_addr_key(42, 700, 0x1000);
    const go_exact_process_addr_key_t request_b = go_exact_process_addr_key(42, 700, 0x2000);

    assert_bool(1,
                go_http1_stage_header_request(&locator_map, 0xa000, 0xb000, &request_a),
                "stage first shared Header request");
    assert_bool(1,
                go_http1_stage_header_request(&locator_map, 0xa000, 0xc000, &request_b),
                "stage second shared Header request");
    assert_bool(2, locator_count(), "shared Header retains both connections");

    go_exact_process_addr_key_t taken = {};
    assert_bool(1,
                go_http1_take_header_request(&locator_map, 42, 700, 0xa000, 0xc000, &taken),
                "take shared Header on second connection");
    assert_exact(&request_b, &taken, "second connection resolves its request");
    assert_bool(1,
                go_http1_take_header_request(&locator_map, 42, 700, 0xa000, 0xb000, &taken),
                "take shared Header on first connection");
    assert_exact(&request_a, &taken, "first connection resolves its request");
}

static void test_same_composite_reuse_replaces_missed_locator(void) {
    reset_maps();
    const go_exact_process_addr_key_t old_request = go_exact_process_addr_key(42, 700, 0x1000);
    const go_exact_process_addr_key_t new_request = go_exact_process_addr_key(42, 700, 0x2000);

    go_http1_stage_header_request(&locator_map, 0xa000, 0xb000, &old_request);
    go_http1_stage_header_request(&locator_map, 0xa000, 0xb000, &new_request);
    assert_bool(1, locator_count(), "same composite has one current locator");

    go_exact_process_addr_key_t taken = {};
    assert_bool(1,
                go_http1_take_header_request(&locator_map, 42, 700, 0xa000, 0xb000, &taken),
                "take reused composite locator");
    assert_exact(&new_request, &taken, "reused composite cannot revive old request");
}

static void test_process_reuse_and_corrupt_locator_fail_closed(void) {
    reset_maps();
    const go_exact_process_addr_key_t old_request = go_exact_process_addr_key(42, 700, 0x1000);
    go_http1_stage_header_request(&locator_map, 0xa000, 0xb000, &old_request);

    go_exact_process_addr_key_t taken = {};
    assert_bool(0,
                go_http1_take_header_request(&locator_map, 42, 701, 0xa000, 0xb000, &taken),
                "PID reuse cannot consume an old locator");
    assert_bool(1, locator_count(), "new process cannot delete old exact locator");

    locators[0].request.process_start_time = 699;
    assert_bool(0,
                go_http1_take_header_request(&locator_map, 42, 700, 0xa000, 0xb000, &taken),
                "corrupt locator value fails closed");
    assert_bool(0, locator_count(), "failed exact claim consumes corrupt locator");

    assert_bool(0,
                go_http1_stage_header_request(&locator_map, 0xa000, 0, &old_request),
                "missing persistConn cannot publish Header-only fallback");
}

static void test_write_subset_entry_clears_same_process_missed_return(void) {
    reset_maps();
    writer_key = go_exact_process_addr_key(42, 700, 0xd000);
    writer_present = 1;

    go_http1_begin_write_subset(&writer_map, &writer_key);
    assert_bool(0, writer_present, "entry clears same-process slot before later parameter failure");

    writer_key = go_exact_process_addr_key(42, 700, 0xd000);
    writer_present = 1;
    const go_exact_process_addr_key_t reused = go_exact_process_addr_key(42, 701, 0xd000);
    go_http1_begin_write_subset(&writer_map, &reused);
    assert_bool(1, writer_present, "new process cannot alias old writer slot");
    assert_bool(1,
                memcmp(&writer_key, &reused, sizeof(writer_key)) != 0,
                "PID and goroutine reuse remains exact-process scoped");
}

int main(void) {
    test_shared_header_is_connection_scoped();
    test_same_composite_reuse_replaces_missed_locator();
    test_process_reuse_and_corrupt_locator_fail_closed();
    test_write_subset_entry_clears_same_process_missed_return();
    return failures ? 1 : 0;
}
