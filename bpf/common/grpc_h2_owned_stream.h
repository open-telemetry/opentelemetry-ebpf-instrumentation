// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct grpc_h2_owned_stream_key {
    u64 socket_cookie;
    u32 pid;
    u32 stream_id;
} grpc_h2_owned_stream_key_t;
