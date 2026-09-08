// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// client_trace_parent (gotracer/go_common.h) fills the trace context for an
// outgoing Go client call. Callers pass it memory that still holds the previous
// request's ids, so every field that is not copied from a real parent has to be
// written explicitly. A client call with no parent request that leaves
// parent_id alone emits a span whose parent belongs to an unrelated trace and
// is never sent, which makes the trace rootless; a call adopted from a SQL
// wrapper that leaves span_id alone emits a duplicate span id.
//
// Run from repo root:
//   make -C bpf/tests bpf_go_client_trace_parent && bpf/tests/bpf_go_client_trace_parent

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Called by the go_common.h include chain, omitted by the shared stub
#define BPF_ANY 0

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

struct file {
    struct inode *f_inode;
};

struct mm_struct {
    struct file *exe_file;
};

#define GO_PARAM2(x) ((void *)(x)->bx)

#include <gotracer/go_common.h>

static void expect(bool got, bool want, const char *message) {
    if (got != want) {
        fprintf(stderr, "FAIL: %s (want %d, got %d)\n", message, want, got);
        exit(1);
    }
}

static sql_func_invocation_t *sql_wrapper;

static void *sql_wrapper_lookup(void *map, const void *key) {
    return map == &ongoing_sql_queries ? sql_wrapper : NULL;
}

static void no_parent_request(void) {
    tp_info_t tp;

    memset(&tp, 0xAB, sizeof(tp));

    const u8 found = client_trace_parent((void *)0x1234, &tp);

    expect(found == 0, true, "no parent request is found when the maps are empty");
    expect(valid_span(tp.parent_id),
           false,
           "a client call with no parent request must not inherit a parent id from the "
           "previous occupant of the scratch buffer");
    expect(valid_span(tp.span_id), true, "a client call always gets its own span id");
}

static void parent_is_a_sql_wrapper(void) {
    sql_func_invocation_t invocation = {};
    tp_info_t tp;
    unsigned char stale[SPAN_ID_SIZE_BYTES];

    memset(invocation.tp.trace_id, 0x11, sizeof(invocation.tp.trace_id));
    memset(invocation.tp.span_id, 0x22, sizeof(invocation.tp.span_id));

    memset(&tp, 0xAB, sizeof(tp));
    memset(stale, 0xAB, sizeof(stale));

    sql_wrapper = &invocation;
    bpf_map_lookup_elem_hook = sql_wrapper_lookup;
    const u8 found = client_trace_parent((void *)0x1234, &tp);
    bpf_map_lookup_elem_hook = NULL;

    expect(found == 1, true, "a cloud web database wrapping the call is adopted as the parent");
    expect(memcmp(tp.parent_id, invocation.tp.span_id, sizeof(tp.parent_id)) == 0,
           true,
           "the adopted parent's span id becomes the client call's parent id");
    expect(memcmp(tp.span_id, stale, sizeof(tp.span_id)) != 0,
           true,
           "a client call adopted from a SQL wrapper must not keep the span id left in the "
           "scratch buffer");
    expect(valid_span(tp.span_id), true, "the adopted client call still gets its own span id");
}

int main(void) {
    no_parent_request();
    parent_is_a_sql_wrapper();

    printf("OK: %s\n", __FILE__);
    return 0;
}
