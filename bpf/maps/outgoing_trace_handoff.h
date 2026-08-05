// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/egress_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

typedef struct outgoing_trace_handoff {
    tp_info_pid_t tp;
    u64 created_at;
    u64 last_progress;
    u64 terminal_at;
    u8 local_consumed;
    u8 retire_requested;
    u8 terminal_reason;
    u8 _pad[5];
} outgoing_trace_handoff_t;

enum outgoing_trace_terminal_reason : u8 {
    k_outgoing_trace_terminal_none,
    k_outgoing_trace_terminal_durable,
    k_outgoing_trace_terminal_owner_cleanup,
    k_outgoing_trace_terminal_dead_process,
    k_outgoing_trace_terminal_expired,
};

typedef struct outgoing_trace_handoff_key {
    egress_key_t egress;
    u32 _pad;
    outgoing_trace_token_t token;
} outgoing_trace_handoff_key_t;

// Transport reservations are immutable generations. An old operation can
// therefore only address its own generation, even after the egress tuple is
// reused by a keepalive request.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, outgoing_trace_handoff_key_t);
    __type(value, outgoing_trace_handoff_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} outgoing_trace_handoff SEC(".maps");

// Non-authoritative egress -> generation locator. Every reader must follow it
// with an exact lookup in outgoing_trace_handoff. Reservation and conditional
// locator cleanup are serialized by outgoing_trace_handoff_egress_claims.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, egress_key_t);
    __type(value, outgoing_trace_token_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} outgoing_trace_handoff_locators SEC(".maps");

// Exact-generation operation claims. Writers claim before touching user or
// packet bytes; consumers claim before publishing local state; cleanup either
// claims or requests deferred retirement.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, outgoing_trace_handoff_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} outgoing_trace_handoff_claims SEC(".maps");

// Short-lived egress claims serialize reservation and locator maintenance.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, egress_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} outgoing_trace_handoff_egress_claims SEC(".maps");

// Per-CPU generation state shares the lifetime of the pinned authority maps.
// Token allocation deliberately avoids atomic-fetch instructions that older
// supported kernels reject.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} outgoing_trace_handoff_sequence SEC(".maps");

// Serializes access to each per-CPU counter across the current non-NMI
// tracing/socket producer set. Contention fails closed before wire mutation.
// Do not add an NMI producer without a separate synchronization proof.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} outgoing_trace_handoff_cpu_claims SEC(".maps");

// Initialized by the loader, while it holds the shared-map lock, to the live
// kernel map ID of outgoing_trace_handoff. It is never initialized or reset
// by a BPF producer.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} outgoing_trace_handoff_epoch SEC(".maps");
