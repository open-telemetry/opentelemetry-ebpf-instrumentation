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

typedef struct kafka_go_produce_request_topic {
    go_string_t topic;
    go_slice_t partitions;
} kafka_go_produce_request_topic_t;

typedef struct kafka_go_produce_request {
    go_string_t transactional_id;
    s16 acks;
    u8 _pad1[2];
    s32 timeout;
    go_slice_t topics;
} kafka_go_produce_request_t;

typedef struct topic {
    char name[k_max_topic_name_len];
    tp_info_t tp;
} topic_t;
