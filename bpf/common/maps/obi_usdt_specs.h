// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <common/pin_internal.h>
#include <common/usdt_types.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, k_obi_usdt_max_spec_cnt);
    __type(key, u32);
    // Value describes how to read one USDT probe's arguments.
    __type(value, struct obi_usdt_spec);
    __uint(pinning, OBI_PIN_INTERNAL);
} obi_usdt_specs SEC(".maps");
