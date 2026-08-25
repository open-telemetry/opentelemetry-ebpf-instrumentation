// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/scratch_mem.h>
#include <common/tls_record.h>

// Scratch space for building a correlation key.
//
// tcp_sendmsg is already close to the 512 byte BPF stack limit, so the key and
// the bytes it is built from live in per-CPU scratch.
SCRATCH_MEM_TYPED(tls_prefix, tls_prefix_scratch_t);
