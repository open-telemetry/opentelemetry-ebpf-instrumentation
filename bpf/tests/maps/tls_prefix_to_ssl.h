// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/bpf_helpers.h>

#include <common/tls_record.h>

extern struct bpf_test_map tls_prefix_to_ssl;
