// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include "k_tcp.c"
#include "tp_tcp.c"

// Force emitting these enums into the ELF so bpf2go generates their Go constants
const enum stat_type *unused_1 __attribute__((unused));
const enum tcp_fail_reason *unused_2 __attribute__((unused));
const enum tcp_handshake_role *unused_3 __attribute__((unused));
const enum network_io_direction *unused_4 __attribute__((unused));

char __license[] SEC("license") = "Dual MIT/GPL";
