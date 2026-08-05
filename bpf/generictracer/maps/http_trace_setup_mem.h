// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>

typedef struct http_trace_setup_scratch {
    egress_key_t egress;
    u32 _pad;
    outgoing_trace_token_t handoff_token;
} http_trace_setup_scratch_t;

static __always_inline void
prepare_http_trace_setup_scratch(http_trace_setup_scratch_t *scratch,
                                 const pid_connection_info_t *pid_conn,
                                 const outgoing_trace_token_t *handoff_token,
                                 u8 handoff_expected) {
    make_egress_key_into(&scratch->egress, &pid_conn->conn, pid_conn->pid, 0);
    if (handoff_expected) {
        scratch->handoff_token = *handoff_token;
    } else {
        __builtin_memset(&scratch->handoff_token, 0, sizeof(scratch->handoff_token));
    }
}

SCRATCH_MEM_TYPED(http_trace_setup, http_trace_setup_scratch_t);
