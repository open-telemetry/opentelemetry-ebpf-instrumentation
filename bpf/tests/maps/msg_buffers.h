// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/bpf_helpers.h>

#include <common/egress_key.h>
#include <common/msg_buffer.h>

extern struct bpf_test_map msg_buffers;
