// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// These need to line up with some Go identifiers defined in the appnetworktracer.go file
#pragma once
enum {
    event_app_net_tcp_rtt = 1, // EventTypeAppNetTcpRtt
};
