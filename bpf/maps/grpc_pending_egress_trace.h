// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/egress_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

// Go gRPC NewStream-entry trace, keyed by {s_port, d_port, stream_id=0}.
// Race-free fallback when grpcFramerWriteHeaders runs before NewStream_Returns.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, egress_key_t);
    __type(value, tp_info_pid_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} grpc_pending_egress_trace SEC(".maps");
