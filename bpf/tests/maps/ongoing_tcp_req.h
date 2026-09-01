// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/connection_info.h>

extern struct bpf_test_map ongoing_tcp_req;
