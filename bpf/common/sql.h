// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/strings.h>

enum {
    k_max_query_offset = 8,

    k_max_sql_op_len = 6, // Maximum length of SQL operation names (e.g., "SELECT")
};

#define DEFINE_OP(op)                                                                              \
    static const char op##_op[] = #op;                                                             \
    static const u8 op_##op##_len = sizeof(#op) - 1;

#define CHECK_OP(op)                                                                               \
    if (stricmp(stmt, op##_op, op_##op##_len))                                                     \
        return true;

// Define SQL operations that we want to detect in SQL queries.
// NOTE: when adding a new operation, make sure to update the `k_max_sql_op_len`
// constant if needed.
#define FOREACH_OP(fn) fn(WITH) fn(ALTER) fn(SELECT) fn(INSERT) fn(UPDATE) fn(DELETE) fn(CREATE)

FOREACH_OP(DEFINE_OP)

static __always_inline bool is_sql_query_stmt(void *data) {
    char stmt[k_max_sql_op_len];
    if ((bpf_probe_read(&stmt, k_max_sql_op_len, data)) != 0) {
        return false;
    }

    if (stmt[0] == '\0') {
        return false;
    }

    FOREACH_OP(CHECK_OP)

    return false;
}

// Returns the index of the first character of the SQL query in the buffer.
// Some SQL packets contain some flags which are not a part of the SQL query.
// Returns -1 if the buffer doesn't contain an SQL query.
static __always_inline int find_sql_query(void *data) {
    for (u8 i = 0; i < k_max_query_offset; i++) {
        if (is_sql_query_stmt(data + i)) {
            return i;
        }
    }
    return -1;
}
