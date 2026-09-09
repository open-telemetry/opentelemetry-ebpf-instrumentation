// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// valid_pid() (pid/pid.h) runs at the top of every kprobe, for every process
// on the node. Its answer is cached in pid_cache keyed by host pid; both the
// selected and the not-selected answer must be cached, otherwise a process OBI
// was never asked to watch pays the ns_pid_ppid() namespace walk on every
// syscall. Userspace clears pid_cache when the filter changes, which is what
// makes a cached "not selected" safe for children authorized through their
// parent later on.
//
// Run from repo root:
//   make -C bpf/tests bpf_pid_filter && bpf/tests/bpf_pid_filter

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
// included ahead of the override below, so the include chain does not redefine it
#include <bpfcore/bpf_core_read.h>

// Omitted by the shared stub
#define BPF_ANY 0
#define BPF_NOEXIST 1

// Host-resident structs, so a direct field-chain access stands in for the
// CO-RE read. The shared stub returns a zero value instead.
#undef BPF_CORE_READ
#define BPF_CORE_READ(src, ...)                                                                    \
    (___bpf_apply(___bpf_arrow, ___bpf_narg(__VA_ARGS__))(src, ##__VA_ARGS__))

// filter_pids is volatile const in pid.h, set from userspace at load time.
// Turning the definition into a pointer lets the tests flip it per case.
#define filter_pids (*test_filter_pids)

// ns_pid_ppid() is the only caller of bpf_probe_read_kernel in this chain, so
// counting its calls tells whether valid_pid() took the slow path.
static u32 test_probe_reads;

static long test_probe_read_kernel(void *dst, u32 size, const void *src) {
    test_probe_reads++;
    memcpy(dst, src, size);
    return 0;
}

static void *test_current_task;

static void *test_get_current_task(void) {
    return test_current_task;
}

// Array-backed simulation of the pid_cache LRU map
enum { k_test_cache_entries = 16 };

typedef struct test_cache_entry {
    bool used;
    u32 key;
    u32 value;
} test_cache_entry_t;

static test_cache_entry_t test_cache[k_test_cache_entries];
static void *test_pid_cache_map;
static void *test_valid_pids_map;
static u64 test_valid_pids[3001];

static test_cache_entry_t *test_cache_find(u32 key) {
    for (u32 i = 0; i < k_test_cache_entries; i++) {
        if (test_cache[i].used && test_cache[i].key == key) {
            return &test_cache[i];
        }
    }
    return NULL;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == test_valid_pids_map) {
        const u32 segment = *(const u32 *)key;
        return segment < 3001 ? &test_valid_pids[segment] : NULL;
    }

    if (map == test_pid_cache_map) {
        test_cache_entry_t *e = test_cache_find(*(const u32 *)key);
        return e ? &e->value : NULL;
    }

    return NULL;
}

// flags of the most recent update, so tests can check which insert used BPF_NOEXIST
static u64 test_last_update_flags;

static long test_map_update(void *map, const void *key, const void *value, u64 flags) {
    if (map != test_pid_cache_map) {
        return -1;
    }

    test_last_update_flags = flags;

    test_cache_entry_t *e = test_cache_find(*(const u32 *)key);
    if (e) {
        e->value = *(const u32 *)value;
        return 0;
    }

    for (u32 i = 0; i < k_test_cache_entries; i++) {
        if (!test_cache[i].used) {
            test_cache[i].used = true;
            test_cache[i].key = *(const u32 *)key;
            test_cache[i].value = *(const u32 *)value;
            return 0;
        }
    }

    return -1;
}

#define bpf_probe_read_kernel test_probe_read_kernel
#define bpf_get_current_task test_get_current_task
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update

#include <pid/pid.h>

#undef bpf_probe_read_kernel
#undef bpf_get_current_task
#undef bpf_map_lookup_elem
#undef bpf_map_update_elem

// Userspace side (generictracer.go), simulated

static s32 test_filter_value = 1;

// mirrors buildPidFilter(): set the bit for (ns, pid) in the valid_pids bitset
static void test_filter_allow(u32 ns, u32 pid) {
    const u64 k = (((u64)ns) << 32) | pid;
    const u32 h = (u32)(k % k_prime_hash);
    test_valid_pids[h / 64] |= ((u64)1 << (h & 63));
}

// mirrors clearPidCache(), run after every rebuildValidPids()
static void test_cache_clear(void) {
    memset(test_cache, 0, sizeof(test_cache));
}

// mirrors AllowPID()'s positive Put, keyed by host pid
static void test_cache_put(u32 host_pid) {
    test_map_update(test_pid_cache_map, &host_pid, &host_pid, BPF_ANY);
}

// Fake tasks. All processes live in one pid namespace, one level below the
// host, so the host pid and the namespaced pid differ.

enum { k_test_ns_level = 1, k_test_ns_inum = 4026531836 };

typedef struct test_task {
    struct task_struct task;
    struct pid thread_pid;
    struct nsproxy nsproxy;
    struct pid_namespace pid_ns;
} test_task_t;

static void test_task_init(test_task_t *t, u32 host_pid, u32 ns_pid, test_task_t *parent) {
    memset(t, 0, sizeof(*t));

    t->pid_ns.level = k_test_ns_level;
    t->pid_ns.ns.inum = k_test_ns_inum;
    t->nsproxy.pid_ns_for_children = &t->pid_ns;
    t->thread_pid.numbers[k_test_ns_level].nr = (int)ns_pid;

    t->task.pid = (int)host_pid;
    t->task.tgid = (int)host_pid;
    t->task.group_leader = &t->task;
    t->task.real_parent = parent ? &parent->task : &t->task;
    t->task.nsproxy = &t->nsproxy;
    t->task.thread_pid = &t->thread_pid;
}

static u32 run_valid_pid(test_task_t *t) {
    test_current_task = &t->task;
    return valid_pid(to_pid_tgid((u32)t->task.tgid, (u32)t->task.pid));
}

// Test harness

static int failures = 0;

static void check_u32(const char *name, u32 expected, u32 actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", name, expected, actual);
        failures++;
        return;
    }
    printf("ok: %s\n", name);
}

static void reset(void) {
    memset(test_valid_pids, 0, sizeof(test_valid_pids));
    test_cache_clear();
    test_probe_reads = 0;
    test_filter_value = 1;
}

static void test_selected_process_is_cached_by_host_pid(void) {
    reset();
    test_task_t proc;
    test_task_init(&proc, 12345, 7, NULL);
    test_filter_allow(k_test_ns_inum, 7);

    check_u32("a selected process returns its host pid", 12345, run_valid_pid(&proc));
    check_u32("the positive insert may overwrite (BPF_ANY)", BPF_ANY, test_last_update_flags);
    check_u32("the positive entry is keyed by the host pid", 1, test_cache_find(12345) != NULL);
    check_u32("no entry is keyed by the namespaced pid", 1, test_cache_find(7) == NULL);

    const u32 reads = test_probe_reads;
    check_u32("a selected process stays selected", 12345, run_valid_pid(&proc));
    check_u32("the second call is served from the cache", reads, test_probe_reads);
}

static void test_unselected_process_takes_the_slow_path_once(void) {
    reset();
    test_task_t proc;
    test_task_init(&proc, 555, 12, NULL);

    check_u32("an unselected process is rejected", 0, run_valid_pid(&proc));
    check_u32("the first call walks the namespaces", 2, test_probe_reads);
    check_u32("the negative insert never clobbers an existing entry (BPF_NOEXIST)",
              BPF_NOEXIST,
              test_last_update_flags);

    check_u32("an unselected process stays rejected", 0, run_valid_pid(&proc));
    check_u32("the second call does not walk the namespaces again", 2, test_probe_reads);

    test_cache_entry_t *e = test_cache_find(555);
    check_u32("the negative entry is keyed by the host pid", 1, e != NULL);
    check_u32("the negative entry holds zero", 0, e ? e->value : 1);
}

// The staleness #2814 reverted #2620 for: a worker forked before discovery
// authorizes its parent. The rebuild that authorizes the parent clears the
// cache, so the worker is re-evaluated and matches through its parent.
static void test_parent_authorized_later_is_reevaluated_after_clear(void) {
    reset();
    test_task_t master, worker;
    test_task_init(&master, 599, 1, NULL);
    test_task_init(&worker, 600, 2, &master);

    check_u32("a worker of an unselected master is rejected", 0, run_valid_pid(&worker));

    test_filter_allow(k_test_ns_inum, 1);
    check_u32("the stale negative still rejects the worker before the cache is cleared",
              0,
              run_valid_pid(&worker));

    test_cache_clear();
    check_u32(
        "after the clear the worker is accepted through its parent", 600, run_valid_pid(&worker));
    check_u32("the worker is now cached positive", 1, test_cache_find(600) != NULL);
}

static void test_userspace_positive_overrides_negative(void) {
    reset();
    test_task_t proc;
    test_task_init(&proc, 700, 3, NULL);

    check_u32("the process starts out rejected", 0, run_valid_pid(&proc));

    test_cache_put(700);
    const u32 reads = test_probe_reads;
    check_u32("a userspace positive put wins", 700, run_valid_pid(&proc));
    check_u32("and needs no namespace walk", reads, test_probe_reads);
}

static void test_filter_off_accepts_everything(void) {
    reset();
    test_filter_value = 0;
    test_task_t proc;
    test_task_init(&proc, 800, 4, NULL);

    check_u32("with the filter off the host pid comes back", 800, run_valid_pid(&proc));
    check_u32("without touching the namespaces", 0, test_probe_reads);
    check_u32("and without touching the cache", 1, test_cache_find(800) == NULL);
}

static void test_unreadable_pid_is_not_cached(void) {
    reset();
    test_task_t proc;
    test_task_init(&proc, 900, 0, NULL);

    check_u32("a process whose namespaced pid reads as zero is rejected", 0, run_valid_pid(&proc));
    check_u32("but not cached, so it is retried", 1, test_cache_find(900) == NULL);
}

int main(void) {
    test_pid_cache_map = &pid_cache;
    test_valid_pids_map = &valid_pids;
    test_filter_pids = &test_filter_value;

    test_selected_process_is_cached_by_host_pid();
    test_unselected_process_takes_the_slow_path_once();
    test_parent_authorized_later_is_reevaluated_after_clear();
    test_userspace_positive_overrides_negative();
    test_filter_off_accepts_everything();
    test_unreadable_pid_is_not_cached();

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all pid filter tests passed\n");
    return 0;
}
