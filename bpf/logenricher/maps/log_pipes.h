// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <logenricher/types.h>

// stdout/stderr pipes of tracked processes, registered from userspace;
// not an LRU (silent eviction would stop capture for live pipes), sized for
// two pipes per log_enricher_pids entry
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, log_pipe_key_t);
    __type(value, u8);
    __uint(max_entries, 1 << 13);
    __uint(pinning, OBI_PIN_INTERNAL);
} log_pipes SEC(".maps");
