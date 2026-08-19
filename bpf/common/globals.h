// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

volatile const bool g_bpf_debug = false;
volatile const bool g_bpf_traceparent_enabled = false;
volatile const bool g_bpf_header_propagation = false;
volatile const bool g_bpf_probe_write_user_enabled = false;
volatile const bool g_bpf_loop_enabled = false;
