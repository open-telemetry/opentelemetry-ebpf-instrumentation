// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tls_record.h>

// LRU map, we don't clean-it up at the moment, which holds onto the mapping
// of the SSL pointer and the current connection. It's setup by the tcp_sendmsg uprobe
// when it's sandwitched between ssl_handshake entry/exit.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_ptr_key_t);               // forked workers can hold the same SSL address
    __type(value, ssl_pid_connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ssl_to_conn SEC(".maps");
