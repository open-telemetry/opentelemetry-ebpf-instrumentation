// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, int);
    __uint(max_entries, 1 << 14);
    __uint(pinning, OBI_PIN_INTERNAL);
} pid_fd SEC(".maps");
