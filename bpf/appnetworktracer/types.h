// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// These need to line up with some Go identifiers defined in the appnetworktracer.go file
#define EVENT_APP_NET_TCP_RTT 1 // EventTypeAppNetTcpRtt
