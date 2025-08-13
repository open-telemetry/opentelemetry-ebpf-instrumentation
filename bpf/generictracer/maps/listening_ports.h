// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/sock_port_ns.h>
#include <common/map_sizing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct sock_port_ns);
    __type(value, bool);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} listening_ports SEC(".maps");
