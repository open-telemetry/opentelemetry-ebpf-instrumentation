// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/scratch_mem.h>

#include <generictracer/http2_client_lifecycle.h>

SCRATCH_MEM_TYPED(http2_client_lifecycle, http2_client_lifecycle_scratch_t)
