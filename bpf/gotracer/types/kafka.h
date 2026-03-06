// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/tp_info.h>

enum {
    k_kafka_api_fetch = 0,
    k_kafka_api_produce = 1,
    k_kafka_api_key_pos = 5,
};

typedef struct produce_req {
    u64 msg_ptr;
    u64 conn_ptr;
    u64 start_monotime_ns;
} produce_req_t;

typedef struct topic {
    char name[MAX_TOPIC_NAME_LEN];
    tp_info_t tp;
} topic_t;
