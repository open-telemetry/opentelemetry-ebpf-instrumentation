// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/pin_internal.h>

struct listener_pid_key {
    u64 netns_cookie;
    u32 local_port;
    u32 pad;
};

struct listener_pid_val {
    u64 pid_tgid;
    pid_info pid_info;
    pid_key_t pid_key;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, struct listener_pid_key);
    __type(value, struct listener_pid_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} listener_pid_map SEC(".maps");
