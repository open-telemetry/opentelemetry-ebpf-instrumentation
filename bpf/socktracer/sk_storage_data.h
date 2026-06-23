// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

struct sk_storage_data {
    u64 sk_cookie;
    u64 pid_tgid;
};
