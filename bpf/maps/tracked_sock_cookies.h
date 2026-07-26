// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Context for future maintainers: this code was added to mitigate a bug in the Linux kernel that
// was fixed a few weeks after being reported (July 2026), but had already reached some users'
// production environments from version 6.x onwards (via backports). This mitigation code will be
// kept here for an undetermined, long period of time, until it is safe to assume that no trace of
// the buggy kernel versions remains.
// Original report impacting OBI users: https://github.com/grafana/beyla/issues/2941
// Kernel bug fix and merge notification thread:
// https://lore.kernel.org/bpf/20260708-fionread-no-verdict-v3-0-b4ee31b3af53@coralogix.com/

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
