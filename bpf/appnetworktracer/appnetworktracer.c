// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include "k_tcp.c"
#include "types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Event for application network metrics
const app_net_tcp_rtt_t *unused_1 __attribute((unused));