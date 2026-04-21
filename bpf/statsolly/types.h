// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#pragma once
enum {
    k_event_stat_tcp_rtt = 1,               // StatTypeTCPRtt
    k_event_stat_tcp_failed_connection = 2, // StatTypeTCPFailedConnection
};
