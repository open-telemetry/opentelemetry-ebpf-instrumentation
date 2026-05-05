// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

// Marked by gotracer at grpcFramerWriteHeaders. sk_msg checks via
// is_go_grpc_client_conn and bails — uprobe wrote HPACK in user buffer
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_grpc_client_conns SEC(".maps");
