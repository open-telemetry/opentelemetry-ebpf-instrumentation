// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

volatile const bool g_bpf_debug = false;
volatile const bool g_bpf_traceparent_enabled = false;
volatile const bool g_bpf_header_propagation = false;
volatile const bool g_bpf_probe_write_user_enabled = false;
volatile const bool g_bpf_loop_enabled = false;
volatile const u8 g_go_h2_write_fail_step = 0;
// Set from Config.PopulateTraceContext(): whether anything reads traces_ctx_v1.
// Keeping that map aligned with the active request costs a refresh on every async
// context switch of the instrumented runtime, so with no reader its writers compile
// away and each runtime skips the machinery that drives them (on Node.js, an
// async_hooks before hook running on every callback). Only the writers are gated:
// a reader on an unpopulated map finds nothing, which is what a lookup on a thread
// with no request in flight already returns.
volatile const bool g_trace_ctx_map_enabled = false;
