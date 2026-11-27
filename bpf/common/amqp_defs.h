// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/tp_info.h>

#include <pid/types/pid_info.h>

// AMQP 0-9-1 wire format: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf

enum {
    k_amqp_protocol_header_len = 8,
    k_amqp_protocol_id = 0,
    k_amqp_protocol_version_major = 0,
    k_amqp_protocol_version_minor = 9,
    k_amqp_protocol_version_revision = 1,
    // frame header: type octet, channel short, size long
    k_amqp_frame_header_len = 7,
    k_amqp_frame_size_off = 3,
    k_amqp_frame_end = 0xce,
    k_amqp_method_header_len = 4,
    k_amqp_method_copy_len = 256,
};

enum amqp_frame_type : u8 {
    k_amqp_frame_method = 1,
    k_amqp_frame_content_header = 2,
    k_amqp_frame_body = 3,
    k_amqp_frame_heartbeat = 8,
};

enum {
    k_amqp_class_basic = 60,

    k_amqp_method_publish = 40,
    k_amqp_method_deliver = 60,
    k_amqp_method_get_ok = 71,
    k_amqp_method_ack = 80,
    k_amqp_method_reject = 90,
    k_amqp_method_nack = 120,
};

// A Basic.Publish the process sent, or a Basic.Deliver or Basic.Get-Ok it received
typedef struct amqp_msg_event {
    u8 type; // k_event_type_amqp_message, must be first
    enum parent_status parent_status;
    u16 method_len;
    connection_info_t conn_info; // Client to broker.
    pid_info_t pid;
    u8 _pad[4];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    tp_info_t tp;
    // class id, method id and arguments
    unsigned char method[k_amqp_method_copy_len];
} amqp_msg_event_t;
