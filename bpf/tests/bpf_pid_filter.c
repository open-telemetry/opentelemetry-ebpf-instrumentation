// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// valid_pid() (pid/pid.h) runs at the top of every kprobe, for every process
// on the node. valid_pids holds one bit per pid, keyed by the tgid OBI's /proc
// numbers the task with: the host tgid when OBI runs in the initial pid
// namespace, the pod tgid when it runs as a sidecar. In the sidecar modes a
// task outside the pod is rejected before the map is read.
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

// Host-resident structs, so a direct field-chain access stands in for the
// CO-RE read. The shared stub returns a zero value instead.
#undef BPF_CORE_READ
#define BPF_CORE_READ(src, ...)                                                                    \
    (___bpf_apply(___bpf_arrow, ___bpf_narg(__VA_ARGS__))(src, ##__VA_ARGS__))

// The pid.h constants are volatile const, set from userspace at load time.
// Turning each definition into a pointer lets the tests flip them per case.
#define filter_pids (*test_filter_pids)
#define pid_ns_mode (*test_pid_ns_mode)
#define obi_pid_ns_dev (*test_obi_pid_ns_dev)
#define obi_pid_ns_ino (*test_obi_pid_ns_ino)

static void *test_current_task;
static u32 test_current_task_calls;

static void *test_get_current_task(void) {
    test_current_task_calls++;
    return test_current_task;
}

static long test_probe_read_kernel(void *dst, u32 size, const void *src) {
    memcpy(dst, src, size);
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

// Pid namespaces: the host, a pod below it, a sandbox nested in the pod

static const u64 k_test_nsfs_dev = 4;
static const u32 k_test_host_ino = 0xEFFFFFFC; // PROC_PID_INIT_INO
static const u32 k_test_pod_ino = 4026532500;
static const u32 k_test_nested_ino = 4026532600;

static struct pid_namespace test_host_ns = {.level = 0};
static struct pid_namespace test_pod_ns = {.level = 1};
static struct pid_namespace test_nested_ns = {.level = 2};
static struct pid_namespace *const test_ns_at_level[] = {
    &test_host_ns, &test_pod_ns, &test_nested_ns};

static u32 test_helper_calls;

// bpf_get_ns_current_pid_tgid(): answers only for a task whose own pid
// namespace (task_active_pid_ns) is the one named by dev and ino
static long test_get_ns_current_pid_tgid(unsigned long long dev,
                                         unsigned long long ino,
                                         struct bpf_pidns_info *nsdata,
                                         unsigned int size) {
    test_helper_calls++;

    const struct task_struct *task = test_current_task;
    const unsigned int level = task->thread_pid->level;
    const struct upid *own = &task->thread_pid->numbers[level];

    if (dev != k_test_nsfs_dev || own->ns->ns.inum != ino) {
        memset(nsdata, 0, size);
        return -22; // -EINVAL
    }

    nsdata->pid = (u32)own->nr;
    nsdata->tgid = (u32)task->group_leader->thread_pid->numbers[level].nr;
    return 0;
}

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
static test_task_t unshared; // host 41013, pod 21: called unshare(CLONE_NEWPID), not forked yet
static test_task_t huge;     // host 4194304: past PID_MAX_LIMIT

static void test_cast_init(void) {
    test_task_init(&systemd, (int[]){1}, 0, NULL, &systemd);
    test_task_init(&shim, (int[]){900}, 0, NULL, &systemd);
    test_task_init(&proc, (int[]){41000, 7}, 1, NULL, &shim);
    test_task_init(&child, (int[]){41001, 8}, 1, NULL, &proc);
    test_task_init(&thread, (int[]){41005, 12}, 1, &proc, &shim);
    test_task_init(&outsider, (int[]){555}, 0, NULL, &systemd);
    test_task_init(&sandbox, (int[]){41012, 20, 1}, 2, NULL, &proc);
    test_task_init(&unshared, (int[]){41013, 21}, 1, NULL, &shim);
    unshared.nsproxy.pid_ns_for_children = &test_nested_ns;
    // past its own level; what a reader trusting pid_ns_for_children would pick
    unshared.pid.numbers[2] = (struct upid){.nr = 1, .ns = &test_nested_ns};
    test_task_init(&huge, (int[]){4194304}, 0, NULL, &systemd);
}

static u32 run_valid_pid(test_task_t *t) {
    test_current_task = &t->task;
    return valid_pid(to_pid_tgid((u32)t->task.tgid, (u32)t->task.pid));
}

// Test harness

static s32 test_filter_value;
static u32 test_mode_value;
static u64 test_dev_value;
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
    test_helper_calls = 0;
    test_current_task_calls = 0;

    test_filter_value = 1;
    test_mode_value = mode;
    test_dev_value = k_test_nsfs_dev;
    test_ino_value = mode == k_pid_ns_mode_init ? k_test_host_ino : k_test_pod_ino;
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

// OBI as a sidecar in the pod: keys are pod tgids, tasks outside are rejected

static const char *mode_name(u32 mode) {
    return mode == k_pid_ns_mode_pod_helper ? "pod helper" : "pod emulated";
}

static void check_mode(const char *what, u32 mode, u32 expected, u32 actual) {
    char name[160];
    snprintf(name, sizeof(name), "%s: %s", mode_name(mode), what);
    check_u32(name, expected, actual);
}

static void test_pod_selected_process(u32 mode) {
    reset(mode);
    test_allow(7);

    check_mode("the discovered process passes and returns its pod pid, as userspace knows it",
               mode,
               7,
               run_valid_pid(&proc));
    check_mode("the helper is called only in helper mode",
               mode,
               mode == k_pid_ns_mode_pod_helper,
               test_helper_calls);
}

static void test_pod_child_and_thread(u32 mode) {
    reset(mode);
    test_allow(7);

    check_mode("a child passes through its parent's pod pid", mode, 8, run_valid_pid(&child));
    check_mode("a thread passes on its process's pod pid", mode, 7, run_valid_pid(&thread));
}

static void test_pod_outsider_is_rejected_before_the_map(u32 mode) {
    reset(mode);
    test_allow(7);

    check_mode("a process outside the pod is rejected", mode, 0, run_valid_pid(&outsider));
    check_mode("without reading the map", mode, 0, test_lookups);
}

static void test_pod_pid_does_not_collide_with_host_pid(u32 mode) {
    reset(mode);
    test_allow(1); // the pod's pid 1

    check_mode("host pid 1 does not match the pod's pid 1", mode, 0, run_valid_pid(&systemd));
}

// Documented limitation: bpf_get_ns_current_pid_tgid() answers only for tasks
// whose own pid namespace is OBI's, and the emulated mode applies the same rule.
static void test_pod_nested_pid_namespace_is_rejected(u32 mode) {
    reset(mode);
    test_allow(20); // what userspace publishes: NSpid read from the pod starts at 20

    check_mode("a task in a pid namespace nested in the pod is rejected",
               mode,
               0,
               run_valid_pid(&sandbox));
}

static void test_pod_task_numbered_in_its_own_namespace(u32 mode) {
    reset(mode);
    test_allow(21);

    check_mode("a task that unshared a pid namespace keeps its own number",
               mode,
               21,
               run_valid_pid(&unshared));
}

int main(void) {
    test_filter_pids = &test_filter_value;
    test_pid_ns_mode = &test_mode_value;
    test_obi_pid_ns_dev = &test_dev_value;
    test_obi_pid_ns_ino = &test_ino_value;

    test_host_ns.ns.inum = k_test_host_ino;
    test_pod_ns.ns.inum = k_test_pod_ino;
    test_nested_ns.ns.inum = k_test_nested_ino;

    bpf_map_lookup_elem_hook = test_map_lookup;
    bpf_get_ns_current_pid_tgid_hook = test_get_ns_current_pid_tgid;

    test_cast_init();

    test_init_selected_process_needs_no_task_read();
    test_init_child_passes_through_its_parent();
    test_init_thread_uses_its_process_bit();
    test_init_unselected_and_blocked();
    test_init_pid_beyond_the_bitmap_is_rejected();
    test_filter_off_accepts_everything();

    const u32 pod_modes[] = {k_pid_ns_mode_pod_helper, k_pid_ns_mode_pod_emulated};
    for (u32 i = 0; i < sizeof(pod_modes) / sizeof(pod_modes[0]); i++) {
        test_pod_selected_process(pod_modes[i]);
        test_pod_child_and_thread(pod_modes[i]);
        test_pod_outsider_is_rejected_before_the_map(pod_modes[i]);
        test_pod_pid_does_not_collide_with_host_pid(pod_modes[i]);
        test_pod_nested_pid_namespace_is_rejected(pod_modes[i]);
        test_pod_task_numbered_in_its_own_namespace(pod_modes[i]);
    }

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all pid filter tests passed\n");
    return 0;
}
