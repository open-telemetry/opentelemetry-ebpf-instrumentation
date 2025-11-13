// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <bpfcore/utils.h>

#include <pid/pid_helpers.h>

#include <common/http_types.h>

// TODO: enums
#define K_TCP_MAX_LEN 256
#define K_TCP_RES_LEN 128

#define PATH_MAX_LEN 100
#define PATTERN_MAX_LEN 96
#define METHOD_MAX_LEN 7 // Longest method: OPTIONS
#define REMOTE_ADDR_MAX_LEN                                                                        \
    50 // We need 48: 39(ip v6 max) + 1(: separator) + 7(port length max value 65535) + 1(null terminator)
#define HOST_LEN 64 // can be a fully qualified DNS name
#define TRACEPARENT_LEN 55
#define SQL_MAX_LEN 500
#define KAFKA_MAX_LEN 256
#define REDIS_MAX_LEN 256
#define MONGO_MAX_LEN 256
#define MAX_TOPIC_NAME_LEN 64
#define HOST_MAX_LEN 100
#define SCHEME_MAX_LEN 10
#define HTTP_BODY_MAX_LEN 64
#define HTTP_HEADER_MAX_LEN 100
#define HTTP_CONTENT_TYPE_MAX_LEN 16

enum large_buf_action : u8 {
    k_large_buf_action_init = 0,
    k_large_buf_action_append = 1,
};

enum {
    k_dns_max_len = 512, // must be a power of 2
};

#define MAX_SPAN_NAME_LEN 64
#define MAX_STATUS_DESCRIPTION_LEN 64

// Trace of an HTTP call invocation. It is instantiated by the return uprobe and forwarded to the
// user space through the events ringbuffer.
typedef struct http_request_trace {
    u8 type; // Must be first
    u8 _pad0[1];
    u16 status;
    unsigned char method[METHOD_MAX_LEN];
    unsigned char scheme[SCHEME_MAX_LEN];
    u8 _pad1[11];
    u64 go_start_monotime_ns;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    s64 content_length;
    s64 response_length;
    unsigned char path[PATH_MAX_LEN];
    unsigned char pattern[PATTERN_MAX_LEN];
    unsigned char host[HOST_MAX_LEN];
    tp_info_t tp;
    connection_info_t conn;
    pid_info pid;
} http_request_trace_t;

typedef struct sql_request_trace {
    u8 type; // Must be first
    u8 _pad[1];
    u16 status;
    pid_info pid;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    tp_info_t tp;
    connection_info_t conn;
    unsigned char sql[SQL_MAX_LEN];
} sql_request_trace_t;

typedef struct kafka_client_req {
    u8 type; // Must be first
    u8 _pad[7];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    unsigned char buf[KAFKA_MAX_LEN];
    connection_info_t conn;
    pid_info pid;
} kafka_client_req_t;

typedef struct kafka_go_req {
    u8 type; // Must be first
    u8 op;
    u8 _pad0[2];
    pid_info pid;
    connection_info_t conn;
    u8 _pad1[4];
    tp_info_t tp;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    unsigned char topic[MAX_TOPIC_NAME_LEN];
} kafka_go_req_t;

typedef struct redis_client_req {
    u8 type; // Must be first
    u8 err;
    u8 _pad[6];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    pid_info pid;
    unsigned char buf[REDIS_MAX_LEN];
    connection_info_t conn;
    tp_info_t tp;
} redis_client_req_t;

// Here we track unknown TCP requests that are not HTTP, HTTP2 or gRPC
typedef struct tcp_req {
    u8 flags; // Must be fist we use it to tell what kind of packet we have on the ring buffer
    u8 ssl;
    u8 direction;
    u8 has_large_buffers;
    enum protocol_type protocol_type;
    u8 _pad1[3];
    connection_info_t conn_info;
    u32 len;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u64 extra_id;
    u32 req_len;
    u32 resp_len;
    u8 _pad2[4];
    unsigned char buf[K_TCP_MAX_LEN];
    unsigned char rbuf[K_TCP_RES_LEN];
    // we need this to filter traces from unsolicited processes that share the executable
    // with other instrumented processes
    pid_info pid;
    tp_info_t tp;
} tcp_req_t;

typedef struct tcp_large_buffer {
    u8 type; // Must be first
    u8 packet_type;
    enum large_buf_action action;
    u8 direction;
    u32 len;
    connection_info_t conn_info;
    u32 _pad2;
    tp_info_t tp;
    u8 buf[];
} tcp_large_buffer_t;

typedef struct span_name {
    unsigned char buf[MAX_SPAN_NAME_LEN];
} span_name_t;

typedef struct span_description {
    unsigned char buf[MAX_STATUS_DESCRIPTION_LEN];
} span_description_t;

typedef struct go_string {
    char *str;
    s64 len;
} go_string_t;

typedef struct go_slice {
    void *array;
    s64 len;
    s64 cap;
} go_slice_t;

typedef struct go_iface {
    void *type;
    void *data;
} go_iface_t;

/* Definitions should mimic structs defined in go.opentelemetry.io/otel/attribute */

typedef struct go_otel_attr_value {
    u64 vtype;
    u64 numeric;
    struct go_string string;
    struct go_iface slice;
} go_otel_attr_value_t;

typedef struct go_otel_key_value {
    struct go_string key;
    go_otel_attr_value_t value;
} go_otel_key_value_t;

#define OTEL_ATTRIBUTE_KEY_MAX_LEN (32)
#define OTEL_ATTRIBUTE_VALUE_MAX_LEN (128)
#define OTEL_ATTRIBUTE_MAX_COUNT (16)

typedef struct otel_attribute {
    u16 val_length;
    u8 vtype;
    u8 reserved;
    unsigned char key[OTEL_ATTRIBUTE_KEY_MAX_LEN];
    unsigned char value[OTEL_ATTRIBUTE_VALUE_MAX_LEN];
} otel_attribute_t;

typedef struct otel_attributes {
    otel_attribute_t attrs[OTEL_ATTRIBUTE_MAX_COUNT];
    u8 valid_attrs;
    u8 _apad;
} otel_attributes_t;

typedef struct otel_span {
    u8 type; // Must be first
    u8 _pad[7];
    u64 start_time;
    u64 end_time;
    u64 parent_go;
    tp_info_t tp;
    tp_info_t prev_tp;
    u32 status;
    span_name_t span_name;
    span_description_t span_description;
    pid_info pid;
    otel_attributes_t span_attrs;
    u8 _epad[6];
} otel_span_t;

typedef struct mongo_go_client_req {
    u8 type; // Must be first
    u8 err;
    u8 _pad[6];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    pid_info pid;
    unsigned char op[32];
    unsigned char db[32];
    unsigned char coll[32];
    connection_info_t conn;
    tp_info_t tp;
} mongo_go_client_req_t;

typedef struct dns_req {
    u8 flags; // Must be first we use it to tell what kind of packet we have on the ring buffer
    u8 dns_q;
    u8 _pad1[2];
    u32 len;
    connection_info_t conn;
    u16 id;
    u8 _pad2[2];
    tp_info_t tp;
    // we need this to filter traces from unsolicited processes that share the executable
    // with other instrumented processes
    pid_info pid;
    unsigned char buf[k_dns_max_len];
    u8 _pad3[4];
} dns_req_t;
