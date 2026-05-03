// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include "k_tcp.c"
#include "tp_tcp.c"

char __license[] SEC("license") = "Dual MIT/GPL";
