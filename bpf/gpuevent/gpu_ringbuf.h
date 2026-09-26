// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
    __uint(pinning, OBI_PIN_INTERNAL);
} gpu_events SEC(".maps");
