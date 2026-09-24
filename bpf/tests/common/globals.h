// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Test override of common/globals.h. The agent rewrites these at load time, which
// a native test build cannot do, so they are plain variables here and a test
// assigns the ones it needs. Defaults must mirror common/globals.h.

#pragma once

#include <bpfcore/vmlinux.h>

static bool g_bpf_debug = false;
static bool g_bpf_traceparent_enabled = false;
static bool g_bpf_header_propagation = false;
static bool g_bpf_probe_write_user_enabled = false;
static bool g_bpf_loop_enabled = false;
static u8 g_go_h2_write_fail_step = 0;
static bool g_traces_ctx_v1_enabled = false;
