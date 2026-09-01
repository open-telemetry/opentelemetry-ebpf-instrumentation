// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

#include <generictracer/types/http2_conn_info_data.h>

extern struct bpf_test_map ongoing_http2_connections;
