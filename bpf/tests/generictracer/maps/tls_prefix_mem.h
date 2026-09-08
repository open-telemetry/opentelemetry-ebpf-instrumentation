// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/bpf_helpers.h>

#include <common/tls_record.h>

// The real map is per-CPU scratch; a single-threaded host test just needs one
// instance of the same type.
extern tls_prefix_scratch_t test_tls_prefix_scratch;

static __always_inline void *tls_prefix_mem(void) {
    return &test_tls_prefix_scratch;
}
