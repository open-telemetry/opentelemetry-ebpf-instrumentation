// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

enum {
    // Maximum number of path components we'll grab before we give up.
    k_path_resolver_max_components = 20,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct dentry *[k_path_resolver_max_components]);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} path_resolver_scratch SEC(".maps");
