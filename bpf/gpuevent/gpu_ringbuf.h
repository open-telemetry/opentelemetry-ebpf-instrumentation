// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
} gpu_events SEC(".maps");
