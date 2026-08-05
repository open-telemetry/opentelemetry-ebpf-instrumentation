// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

typedef struct go_h2_client_conn {
    u64 process_start_time;
} go_h2_client_conn_t;

// Marked by gotracer for both net/http2 and gRPC. The marker means Go owns
// traceparent classification for this connection; a missing per-stream exact
// reservation must therefore suppress generic fallback rather than create B.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, go_h2_client_conn_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_grpc_client_conns SEC(".maps");
