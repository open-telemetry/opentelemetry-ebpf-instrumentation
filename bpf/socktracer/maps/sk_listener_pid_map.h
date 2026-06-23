// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Per-socket storage used to associate a PID with a socket at creation time.
// Written by the cgroup/sock program (on socket()), read in cgroup_skb/ingress
// to resolve the server PID before accept() returns.
struct sk_listener_pid_data {
    u64 pid_tgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct sk_listener_pid_data);
    __uint(pinning, OBI_PIN_INTERNAL);
} sk_listener_pid_map SEC(".maps");
