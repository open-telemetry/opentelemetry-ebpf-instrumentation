// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Test override of common/globals.h: the constants are plain variables here, so a
// test can set the ones it needs. g_trace_ctx_map_enabled starts on because the
// tests that include this exercise code paths that a real agent only reaches once
// something reads traces_ctx_v1.

#pragma once

#include <bpfcore/vmlinux.h>

static bool g_bpf_debug = false;
static bool g_bpf_traceparent_enabled = false;
static bool g_bpf_header_propagation = false;
static bool g_bpf_probe_write_user_enabled = false;
static bool g_bpf_loop_enabled = false;
static u8 g_go_h2_write_fail_step = 0;
static bool g_trace_ctx_map_enabled = true;
