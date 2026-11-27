// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Socket filters can't use spin locks, not even in a map value they never lock, so they define
// FLOW_LOCK_PLACEHOLDER.
#ifdef FLOW_LOCK_PLACEHOLDER

struct flow_lock_placeholder {
    __u32 unused;
};

#define FLOW_LOCK struct flow_lock_placeholder

static __always_inline void flow_lock(FLOW_LOCK *lock) {
    (void)lock;
}

static __always_inline void flow_unlock(FLOW_LOCK *lock) {
    (void)lock;
}

#else

#define FLOW_LOCK struct bpf_spin_lock

static __always_inline void flow_lock(FLOW_LOCK *lock) {
    bpf_spin_lock(lock);
}

static __always_inline void flow_unlock(FLOW_LOCK *lock) {
    bpf_spin_unlock(lock);
}

#endif
