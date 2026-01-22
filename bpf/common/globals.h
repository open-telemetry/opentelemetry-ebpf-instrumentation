// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

volatile const bool g_bpf_debug = false;
volatile const bool g_bpf_traceparent_enabled = false;
volatile const bool g_bpf_header_propagation = false;
volatile const bool g_bpf_loop_enabled = false;

// application network metrics
volatile const bool g_bpf_app_net_metrics_tcp_rtt = false;
