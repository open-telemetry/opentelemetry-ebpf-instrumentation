// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build obi_bpf_ignore
#pragma once
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64); // pid_tgid
    __type(value, struct sock *);
} tcp_sendmsg_sock SEC(".maps");
