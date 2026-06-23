// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// FIXME: this map is part of the tpinjector backward-compatibility shim. tpinjector
// writes here so that generictracer kprobes can read the pre-injection packet data.
// Remove together with bpf/tpinjector/ and bpf/common/msg_buffer.h once socktracer is
// the default and tpinjector is retired.

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/egress_key.h>
#include <common/msg_buffer.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, egress_key_t);
    __type(value, msg_buffer_t);
    __uint(max_entries, 1000);
    __uint(pinning, OBI_PIN_INTERNAL);
} msg_buffers SEC(".maps");
