// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// valid_pid() (pid/pid.h) runs at the top of every kprobe, for every process
// on the node. valid_pids holds one bit per pid, keyed by the tgid OBI's /proc
// numbers the task with: the host tgid when OBI runs in the initial pid
// namespace, the tgid in OBI's namespace otherwise (a sidecar, a node that is
// itself a container). In pod mode a task outside OBI's namespace is rejected
// before the map is read; tasks in namespaces below it are numbered at OBI's
// level.
//
// Run from repo root:
//   mise run //bpf/tests:test

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
// included ahead of the override below, so the include chain does not redefine it
#include <bpfcore/bpf_core_read.h>

// Host-resident structs, so a direct field-chain access stands in for the
// CO-RE read. The shared stub returns a zero value instead.
#undef BPF_CORE_READ
#define BPF_CORE_READ(src, ...)                                                                    \
    (___bpf_apply(___bpf_arrow, ___bpf_narg(__VA_ARGS__))(src, ##__VA_ARGS__))

// The pid.h constants are volatile const, set from userspace at load time.
// Turning each definition into a pointer lets the tests flip them per case.
#define filter_pids (*test_filter_pids)
#define pid_ns_mode (*test_pid_ns_mode)
#define obi_pid_ns_ino (*test_obi_pid_ns_ino)

static void *test_current_task;
static u32 test_current_task_calls;

static void *test_get_current_task(void) {
    test_current_task_calls++;
    return test_current_task;
}

// fires once, on the next probe read: a test can act in the middle of a walk
static void (*test_on_next_probe_read)(void);

static long test_probe_read_kernel(void *dst, u32 size, const void *src) {
    memcpy(dst, src, size);

    if (test_on_next_probe_read) {
        void (*fn)(void) = test_on_next_probe_read;
        test_on_next_probe_read = NULL;
        fn();
    }

    return 0;
}

#define bpf_probe_read_kernel test_probe_read_kernel
#define bpf_get_current_task test_get_current_task

// the pointer trick above turns pid_ns_mode's enum initializer into a null pointer
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnon-literal-null-conversion"
#include <pid/pid.h>
#pragma clang diagnostic pop

#undef bpf_probe_read_kernel
#undef bpf_get_current_task

// valid_pids

static u64 test_bits[k_valid_pids_words];
static u32 test_lookups;
static u32 test_missed_lookups;

static void *test_map_lookup(void *map, const void *key) {
    if (map != &valid_pids) {
        return NULL;
    }

    test_lookups++;

    const u32 word = *(const u32 *)key;
    if (word >= k_valid_pids_words) {
        test_missed_lookups++;
        return NULL;
    }

    return &test_bits[word];
}

// Userspace side (generictracer.go rebuildValidPids), simulated

static void test_allow(u32 pid) {
    test_bits[pid / 64] |= (u64)1 << (pid % 64);
}

static void test_block(u32 pid) {
    test_bits[pid / 64] &= ~((u64)1 << (pid % 64));
}

// Pid namespaces: the host, a pod below it, a sandbox nested in the pod, a
// namespace nested in the sandbox, and a second pod beside the first

static const u32 k_test_host_ino = 0xEFFFFFFC; // PROC_PID_INIT_INO
static const u32 k_test_pod_ino = 4026532500;
static const u32 k_test_nested_ino = 4026532600;
static const u32 k_test_nested2_ino = 4026532700;
static const u32 k_test_other_pod_ino = 4026532800;

static struct pid_namespace test_host_ns = {.level = 0};
static struct pid_namespace test_pod_ns = {.level = 1};
static struct pid_namespace test_nested_ns = {.level = 2};
static struct pid_namespace test_nested2_ns = {.level = 3};
static struct pid_namespace test_other_pod_ns = {.level = 1};
static struct pid_namespace *const test_ns_at_level[] = {
    &test_host_ns, &test_pod_ns, &test_nested_ns, &test_nested2_ns};

// Fake tasks

typedef struct test_task {
    struct task_struct task;
    struct pid pid;
    struct nsproxy nsproxy;
} test_task_t;

// numbers[i] is the task's pid at level i, from the host (0) down to its own
// namespace. A thread passes its process as leader; every task has a parent.
static void test_task_init(
    test_task_t *t, const int *numbers, u32 level, test_task_t *leader, test_task_t *parent) {
    memset(t, 0, sizeof(*t));

    t->pid.level = level;
    for (u32 i = 0; i <= level; i++) {
        t->pid.numbers[i].nr = numbers[i];
        t->pid.numbers[i].ns = test_ns_at_level[i];
    }
    t->nsproxy.pid_ns_for_children = test_ns_at_level[level];

    t->task.pid = numbers[0];
    t->task.group_leader = leader ? &leader->task : &t->task;
    t->task.tgid = t->task.group_leader->pid;
    t->task.real_parent = &parent->task;
    t->task.nsproxy = &t->nsproxy;
    t->task.thread_pid = &t->pid;
}

static test_task_t systemd;  // host 1
static test_task_t shim;     // host 900, the container runtime's shim
static test_task_t proc;     // host 41000, pod 7: the discovered process
static test_task_t child;    // host 41001, pod 8: forked by proc after discovery
static test_task_t thread;   // host tid 41005, pod tid 12: a thread of proc
static test_task_t outsider; // host 555: an unrelated process on the node
static test_task_t sandbox;  // host 41012, pod 20, nested 1: in its own pid namespace
static test_task_t deep;     // host 41014, pod 22, nested 2, nested2 1: two levels below the pod
static test_task_t inner;    // host 41015, pod 23, nested 3: forked by sandbox after discovery
static test_task_t unshared; // host 41013, pod 21: called unshare(CLONE_NEWPID), not forked yet
static test_task_t neighbor; // host 42000, other pod 3: a process of another pod
static test_task_t huge;     // host 4194304: past PID_MAX_LIMIT

static void test_cast_init(void) {
    test_task_init(&systemd, (int[]){1}, 0, NULL, &systemd);
    test_task_init(&shim, (int[]){900}, 0, NULL, &systemd);
    test_task_init(&proc, (int[]){41000, 7}, 1, NULL, &shim);
    test_task_init(&child, (int[]){41001, 8}, 1, NULL, &proc);
    test_task_init(&thread, (int[]){41005, 12}, 1, &proc, &shim);
    test_task_init(&outsider, (int[]){555}, 0, NULL, &systemd);
    test_task_init(&sandbox, (int[]){41012, 20, 1}, 2, NULL, &proc);
    test_task_init(&deep, (int[]){41014, 22, 2, 1}, 3, NULL, &sandbox);
    test_task_init(&inner, (int[]){41015, 23, 3}, 2, NULL, &sandbox);
    test_task_init(&unshared, (int[]){41013, 21}, 1, NULL, &shim);
    unshared.nsproxy.pid_ns_for_children = &test_nested_ns;
    // past its own level; what a reader trusting pid_ns_for_children would pick
    unshared.pid.numbers[2] = (struct upid){.nr = 1, .ns = &test_nested_ns};
    test_task_init(&neighbor, (int[]){42000, 3}, 1, NULL, &shim);
    neighbor.pid.numbers[1].ns = &test_other_pod_ns;
    // past its own level, shaped like an entry in the pod: struct pid holds
    // only level + 1 entries, so whatever follows must never be read
    outsider.pid.numbers[1] = (struct upid){.nr = 555, .ns = &test_pod_ns};
    test_task_init(&huge, (int[]){4194304}, 0, NULL, &systemd);
}

static u32 run_valid_pid(test_task_t *t) {
    test_current_task = &t->task;
    return valid_pid(to_pid_tgid((u32)t->task.tgid, (u32)t->task.pid));
}

// Test harness

static s32 test_filter_value;
static u32 test_mode_value;
static u64 test_ino_value;

static int failures = 0;

static void check_u32(const char *name, u32 expected, u32 actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", name, expected, actual);
        failures++;
        return;
    }
    printf("ok: %s\n", name);
}

static void reset(u32 mode) {
    memset(test_bits, 0, sizeof(test_bits));
    test_lookups = 0;
    test_missed_lookups = 0;
    test_current_task_calls = 0;

    test_filter_value = 1;
    test_mode_value = mode;
    test_ino_value = mode == k_pid_ns_mode_init ? k_test_host_ino : k_test_pod_ino;
    obi_pid_ns_level = 0;
    test_on_next_probe_read = NULL;
}

// OBI in the initial pid namespace: keys are host tgids

static void test_init_selected_process_needs_no_task_read(void) {
    reset(k_pid_ns_mode_init);
    test_allow(41000);

    check_u32("init: a selected process passes on its own bit", 41000, run_valid_pid(&proc));
    check_u32("init: without reading the task", 0, test_current_task_calls);
}

static void test_init_child_passes_through_its_parent(void) {
    reset(k_pid_ns_mode_init);
    test_allow(41000);

    check_u32("init: a child forked after discovery passes through its parent",
              41001,
              run_valid_pid(&child));
}

static void test_init_thread_uses_its_process_bit(void) {
    reset(k_pid_ns_mode_init);
    test_allow(41000);

    check_u32("init: a thread passes on its process's bit and returns the tgid",
              41000,
              run_valid_pid(&thread));
}

static void test_init_unselected_and_blocked(void) {
    reset(k_pid_ns_mode_init);
    test_allow(41000);

    check_u32("init: an unselected process is rejected", 0, run_valid_pid(&outsider));

    test_block(41000);
    check_u32("init: a blocked process is rejected on the next call", 0, run_valid_pid(&proc));
}

static void test_init_pid_beyond_the_bitmap_is_rejected(void) {
    reset(k_pid_ns_mode_init);

    check_u32("init: a pid beyond the bitmap is rejected", 0, run_valid_pid(&huge));
    check_u32("init: its word does not exist", 1, test_missed_lookups);
}

static void test_filter_off_accepts_everything(void) {
    reset(k_pid_ns_mode_init);
    test_filter_value = 0;

    check_u32("filter off: the host pid comes back", 555, run_valid_pid(&outsider));
    check_u32("filter off: without reading the map", 0, test_lookups);
}

// OBI in another pid namespace (a sidecar's pod, a node that is a container):
// keys are pids in that namespace, tasks outside it are rejected

static void test_pod_selected_process(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(7);

    check_u32("pod: the discovered process passes and returns its pod pid, as userspace knows it",
              7,
              run_valid_pid(&proc));
    check_u32("pod: OBI's level is learned from it", 1, obi_pid_ns_level);
}

static void test_pod_child_and_thread(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(7);

    check_u32("pod: a child passes through its parent's pod pid", 8, run_valid_pid(&child));
    check_u32("pod: a thread passes on its process's pod pid", 7, run_valid_pid(&thread));
}

static void test_pod_outsider_is_rejected_before_the_map(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(7);

    check_u32("pod: a process outside the pod is rejected", 0, run_valid_pid(&outsider));
    check_u32("pod: without reading the map", 0, test_lookups);
    check_u32("pod: without learning a level from it", 0, obi_pid_ns_level);
}

static void test_pod_task_above_obi_level_is_rejected(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(7);
    test_allow(555);
    run_valid_pid(&proc);

    check_u32("pod: once OBI's level is known, a task above it is rejected without reading past "
              "its own level",
              0,
              run_valid_pid(&outsider));
}

static void test_pod_neighbor_is_rejected(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(3); // the pod's own pid 3, if it has one

    check_u32("pod: a process of another pod is rejected before OBI's level is known",
              0,
              run_valid_pid(&neighbor));

    test_allow(7);
    run_valid_pid(&proc);
    check_u32("pod: and after", 0, run_valid_pid(&neighbor));
}

// Two CPUs walk at once while the level is unknown: the neighbor's walk is
// still reading numbers[] when a task in the pod stores the level. The
// neighbor finds nothing and must not store its 0 over it.
static void test_other_cpu_stores_level_1(void) {
    obi_pid_ns_level = 1;
}

static void test_pod_outsider_walk_keeps_a_level_learned_meanwhile(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(7);
    test_on_next_probe_read = test_other_cpu_stores_level_1;

    check_u32("pod: a neighbor whose walk overlaps another CPU learning the level is rejected",
              0,
              run_valid_pid(&neighbor));
    check_u32("pod: and leaves that level in place", 1, obi_pid_ns_level);
}

static void test_pod_pid_does_not_collide_with_host_pid(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(1); // the pod's pid 1

    check_u32("pod: host pid 1 does not match the pod's pid 1", 0, run_valid_pid(&systemd));
}

// Pods on a node that is itself a container, or a sandbox inside a sidecar's
// pod: userspace publishes the NSpid entry OBI's /proc shows, and the gate
// finds the same entry at OBI's level.
static void test_pod_nested_pid_namespace_is_numbered_at_obi_level(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(20);

    check_u32("pod: a task one namespace below OBI's passes with its pid at OBI's level",
              20,
              run_valid_pid(&sandbox));

    test_allow(22);
    check_u32("pod: two namespaces below too", 22, run_valid_pid(&deep));

    check_u32("pod: a child forked below OBI's namespace passes through its parent's pid at "
              "OBI's level",
              23,
              run_valid_pid(&inner));
}

static void test_pod_level_learned_below_obi_namespace(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(22);

    check_u32(
        "pod: OBI's level is found from a task two namespaces below it", 22, run_valid_pid(&deep));
    check_u32("pod: which is the pod's level", 1, obi_pid_ns_level);
}

// OBI deeper down, as on a kind node inside a Docker-in-Docker runner: its
// namespace is the sandbox's (level 2)
static void test_pod_obi_namespace_two_levels_down(void) {
    reset(k_pid_ns_mode_pod);
    test_ino_value = k_test_nested_ino;
    test_allow(2);

    check_u32("pod, OBI at level 2: a task below it passes with its pid at level 2",
              2,
              run_valid_pid(&deep));
    check_u32("pod, OBI at level 2: the level is learned", 2, obi_pid_ns_level);
    check_u32("pod, OBI at level 2: a task above it is rejected", 0, run_valid_pid(&proc));
}

static void test_pod_task_numbered_in_its_own_namespace(void) {
    reset(k_pid_ns_mode_pod);
    test_allow(21);

    check_u32("pod: a task that unshared a pid namespace keeps its own number",
              21,
              run_valid_pid(&unshared));
}

int main(void) {
    test_filter_pids = &test_filter_value;
    test_pid_ns_mode = &test_mode_value;
    test_obi_pid_ns_ino = &test_ino_value;

    test_host_ns.ns.inum = k_test_host_ino;
    test_pod_ns.ns.inum = k_test_pod_ino;
    test_nested_ns.ns.inum = k_test_nested_ino;
    test_nested2_ns.ns.inum = k_test_nested2_ino;
    test_other_pod_ns.ns.inum = k_test_other_pod_ino;

    bpf_map_lookup_elem_hook = test_map_lookup;

    test_cast_init();

    test_init_selected_process_needs_no_task_read();
    test_init_child_passes_through_its_parent();
    test_init_thread_uses_its_process_bit();
    test_init_unselected_and_blocked();
    test_init_pid_beyond_the_bitmap_is_rejected();
    test_filter_off_accepts_everything();

    test_pod_selected_process();
    test_pod_child_and_thread();
    test_pod_outsider_is_rejected_before_the_map();
    test_pod_task_above_obi_level_is_rejected();
    test_pod_neighbor_is_rejected();
    test_pod_outsider_walk_keeps_a_level_learned_meanwhile();
    test_pod_pid_does_not_collide_with_host_pid();
    test_pod_nested_pid_namespace_is_numbered_at_obi_level();
    test_pod_level_learned_below_obi_namespace();
    test_pod_obi_namespace_two_levels_down();
    test_pod_task_numbered_in_its_own_namespace();

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all pid filter tests passed\n");
    return 0;
}
