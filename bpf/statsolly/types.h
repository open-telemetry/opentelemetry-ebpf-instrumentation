// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#pragma once

#include <bpfcore/vmlinux.h>

// The Go StatType* constants in pkg/internal/statsolly/ebpf/stat.go are derived from this enum
enum stat_type : u8 {
    k_stat_type_tcp_rtt = 1,
    k_stat_type_tcp_failed_connection = 2,
    k_stat_type_tcp_retransmit = 3,
    k_stat_type_tcp_io = 4,
    k_stat_type_tcp_successful_connection = 5,
};

// batch size used in tcp io metric
enum {
    k_tcp_io_batch_size = 10,
};

enum tcp_handshake_role : u8 {
    role_unknown = 0,
    role_client = 1,
    role_server = 2,
};

enum tcp_fail_reason : u8 {
    reason_unknown = 0,
    reason_connection_refused = 1,
    reason_connection_reset = 2,
    reason_timed_out = 3,
    reason_host_unreachable = 4,
    reason_net_unreachable = 5,
    reason_other = 255,
};

enum network_io_direction : u8 {
    direction_receive = 1,
    direction_transmit = 2,
};
