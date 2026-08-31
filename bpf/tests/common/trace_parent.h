// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Shadows common/trace_parent.h, whose real include chain pulls in the Go
// tracer and fourteen map definitions. Parent-trace resolution is not
// exercised by the host tests, so find_trace_* always reports no match.

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/trace_helpers.h>
#include <common/trace_key.h>

static __always_inline void
trace_key_from_pid_tid_with_p_key(trace_key_t *t_key, const pid_key_t *p_key, u64 id) {
    t_key->p_key = *p_key;
    t_key->extra_id = id;
}

static __always_inline u8 find_trace_for_client_request_with_t_key(
    const void *p_conn, u16 orig_dport, const void *t_key, u64 id, u8 lw_thread, void *tp) {
    return 0;
}
