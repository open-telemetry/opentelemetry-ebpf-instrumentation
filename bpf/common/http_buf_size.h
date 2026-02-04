// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

enum { k_kprobes_http2_buf_size = 256 };
enum { k_kprobes_http2_ret_buf_size = 64 };

// should be enough for most URLs, we may need to extend it if not.
#define TRACE_BUF_SIZE 1024 // must be power of 2, we do an & to limit the buffer size
