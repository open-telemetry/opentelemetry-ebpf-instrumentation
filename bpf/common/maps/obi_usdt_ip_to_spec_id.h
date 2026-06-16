// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <common/pin_internal.h>
#include <common/usdt_types.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, k_obi_usdt_max_ip_cnt);
    __type(key, struct obi_usdt_ip_key);
    // Value is an index into obi_usdt_specs.
    __type(value, u32);
    __uint(pinning, OBI_PIN_INTERNAL);
} obi_usdt_ip_to_spec_id SEC(".maps");
