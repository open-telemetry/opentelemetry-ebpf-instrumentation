// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct sock *);
    __type(value, u8);
    __uint(max_entries, 1 << 16);
} sock_role SEC(".maps");
