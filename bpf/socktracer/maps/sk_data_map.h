// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <socktracer/socket_data.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct socket_data);
    __uint(max_entries, 10000);
    __uint(pinning, OBI_PIN_INTERNAL);
} sk_data_map SEC(".maps");
