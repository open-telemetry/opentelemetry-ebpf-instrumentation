// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static inline u32 bpf_get_prandom_u32(void) {
    return 0x5a5a5a5a;
}

static inline long bpf_loop(u32 nr_loops, void *cb, void *ctx, u64 flags) {
    return 0;
}

// Go uprobes read arguments out of pt_regs, and get_offsets_table walks the
// running task to its executable inode. The tests need only enough of each for
// the gotracer headers to compile.
struct pt_regs {
    u64 bx;
};

struct super_block {
    u32 s_dev;
};

struct inode {
    unsigned long i_ino;
    struct super_block *i_sb;
};

struct mm_struct {
    struct file *exe_file;
};

#define GO_PARAM2(x) ((void *)(x)->bx)

#include <gotracer/go_common.h>
#define LIBBPF_PIN_BY_NAME 1
#include "../common/trace_parent.h"

volatile const u64 max_transaction_time = 1000;

static unsigned int python_lookups;
static tp_info_pid_t parent;
static bool have_parent;

static void *parent_lookup(void *map, const void *key) {
    (void)key;
    if (map == &python_thread_state) {
        python_lookups++;
    }
    return map == &server_traces && have_parent ? &parent : NULL;
}

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
    printf("PASS: %s\n", message);
}

int main(void) {
    bpf_map_lookup_elem_hook = parent_lookup;
    pid_connection_info_t conn = {};
    trace_key_t key = {};
    tp_info_t tp = {};
    have_parent = true;
    parent.valid = 1;
    parent.tp.trace_id[0] = 1;
    parent.tp.span_id[0] = 2;

    expect(find_parent_trace_with_user_reads(&conn, 1, k_lw_thread_none, &key, 53, false) ==
               &parent,
           "socket path still finds a parent from maps");
    expect(python_lookups == 0, "socket path does not resolve Python user-memory state");
    expect(find_parent_trace(&conn, 1, k_lw_thread_none, &key, 53) == &parent,
           "existing probe wrapper still finds the parent");
    expect(python_lookups == 1, "existing probe wrapper retains Python lookup");

    python_lookups = 0;
    find_trace_for_client_request_with_t_key_and_user_reads(
        &conn, 53, &key, 1, k_lw_thread_none, &tp, false);
    expect(python_lookups == 0, "client trace lookup preserves the socket restriction");
    expect(tp.trace_id[0] == 1 && tp.parent_id[0] == 2,
           "socket client trace retains the map-backed trace and parent IDs");

    have_parent = false;
    expect(find_parent_trace_with_user_reads(&conn, 1, k_lw_thread_none, &key, 53, false) == NULL,
           "socket path reports no parent when maps have no matching request");
    return 0;
}
