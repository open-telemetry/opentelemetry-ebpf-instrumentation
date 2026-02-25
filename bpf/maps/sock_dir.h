// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// A map of sockets which we track with sock_ops. The sock_msg
// program subscribes to this map and runs for each new socket
// activity
// The map size must be max u16 to avoid accidentally losing
// the socket information
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u32));
} sock_dir SEC(".maps");
