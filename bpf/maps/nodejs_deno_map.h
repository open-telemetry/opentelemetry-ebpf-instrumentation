// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

// nodejs_deno_map correlates an outgoing (client) connection to the incoming
// (server) connection that caused it, for the Deno runtime.
//
// Deno exposes no socket fds to JS, so - unlike nodejs_fd_map, which is keyed by
// fd - this map is keyed by the outgoing connection's ephemeral endpoint
// (FD_CLIENT connection_info_part_t) and holds the incoming request's ephemeral
// endpoint (FD_SERVER connection_info_part_t). The latter keys server_traces_aux,
// letting trace_parent resolve the parent server trace for a client call.
//
// It is populated by the deno.c statx kprobe from the tuples the injected
// fdextractor_deno.js agent encodes into a magic path.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_part_t);   // outgoing client ephemeral endpoint
    __type(value, connection_info_part_t); // incoming server ephemeral endpoint
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} nodejs_deno_map SEC(".maps");
