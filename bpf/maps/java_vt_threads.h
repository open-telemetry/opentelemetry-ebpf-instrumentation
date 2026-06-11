// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <pid/pid_helpers.h>
#include <pid/types/pid_key.h>

// Which Java virtual thread is currently mounted on a given carrier OS
// thread. The Java agent updates it on every VirtualThread.mount() (value =
// the VT's logical Thread id, stable across remounts) and deletes it on
// every unmount(), so an entry exists exactly while a VT is mounted and a
// carrier doing non-VT work is never translated. Both transitions execute
// on the carrier thread itself, so write and delete are in program order.
//
// Must be OBI_PIN_INTERNAL: with context propagation enabled the tpinjector
// sk_msg program (a separate BPF object) performs the client-request parent
// lookup; without internal pinning it would read a private empty copy.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t); // the carrier OS thread
    __type(value, u64);     // the mounted virtual thread's logical id
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_vt_threads SEC(".maps");

// Synthetic-tid marker: real kernel tids never reach bit 31.
#define JAVA_VT_TID_FLAG 0x80000000u

// If the calling kernel thread is currently carrying a Java virtual thread,
// rewrite the tid in p_key to a synthetic, stable per-VT id (the flag bit
// avoids clashing with real kernel tids), so tid-keyed correlation survives
// carrier migration and carrier sharing. Returns 1 if the key was rewritten.
// VT ids are sequential longs and keep their low 31 bits: two VTs can only
// alias after 2^31 VT creations in one JVM, and only if both are in flight
// at the same instant.
static __always_inline u8 java_vt_translate_tid(pid_key_t *p_key) {
    const u64 *vt_id = bpf_map_lookup_elem(&java_vt_threads, p_key);
    if (vt_id) {
        p_key->tid = JAVA_VT_TID_FLAG | ((u32)*vt_id & ~JAVA_VT_TID_FLAG);
        return 1;
    }
    return 0;
}

// True if the calling kernel thread is currently carrying a Java virtual
// thread. Used to keep VT-handled requests out of traces_ctx_v1: that map
// is keyed by raw pid_tgid, and under virtual threads a carrier-keyed entry
// would attribute the request's context to whatever runs on the carrier
// next.
static __always_inline u8 java_vt_mounted(void) {
    pid_key_t p_key = {0};
    task_tid(&p_key);
    return bpf_map_lookup_elem(&java_vt_threads, &p_key) != NULL;
}
