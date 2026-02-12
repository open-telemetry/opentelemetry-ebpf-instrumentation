// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>

// LRU map, we don't clean-it up at the moment, which holds onto the mapping
// of the pid-tid and the current connection. It's setup by tcp_rcv_established
// in case we miss SSL_do_handshake
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);                         // the pid-tid pair
    __type(value, ssl_pid_connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
} pid_tid_to_conn SEC(".maps");
