// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <logenricher/types.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, char[k_log_event_max_size]);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} zeros SEC(".maps");
