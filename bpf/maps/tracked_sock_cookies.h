// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Cookies of sockets inserted into sock_dir; the FIONREAD fixup uses them
// to identify affected sockets. LRU so stale entries age out
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u8));
    __uint(pinning, OBI_PIN_INTERNAL);
} tracked_sock_cookies SEC(".maps");
