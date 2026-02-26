// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/tp_info.h>

#define KAFKA_API_FETCH 0
#define KAFKA_API_PRODUCE 1
#define KAFKA_API_KEY_POS 5

typedef struct produce_req {
    u64 msg_ptr;
    u64 conn_ptr;
    u64 start_monotime_ns;
} produce_req_t;

typedef struct topic {
    char name[MAX_TOPIC_NAME_LEN];
    tp_info_t tp;
} topic_t;
