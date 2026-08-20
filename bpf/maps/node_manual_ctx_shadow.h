// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <shared/obi_ctx.h>

// Per-thread saved "base" trace context, stashed when the Node.js span bridge
// overrides traces_ctx_v1 to point at an active manual span (the '-mspan/'
// sentinel). The base is the pre-override entry: either the request's SERVER
// context (a real base) or a zeroed all-zero-trace-id marker meaning "no base
// existed" (the override happened outside any request). The span-end handler
// reads the base for root-span parenting, the pop marker restores it, and the
// per-callback '-ctx' / '-noreqctx' refresh clears it (each callback re-derives
// the base and the bridge re-applies the override right after).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, obi_ctx_info_t);
    __uint(max_entries, 1000); // nodejs is single threaded; small like nodejs_fd_map
    __uint(pinning, OBI_PIN_INTERNAL);
} node_manual_ctx_shadow SEC(".maps");
