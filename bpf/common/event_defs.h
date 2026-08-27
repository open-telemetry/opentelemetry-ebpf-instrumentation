// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

// These must line up with the EventType* constants in pkg/ebpf/common/common.go.
enum event_type : u8 {
    EVENT_HTTP_REQUEST = 1,
    EVENT_GRPC_REQUEST = 2,
    EVENT_HTTP_CLIENT = 3,
    EVENT_GRPC_CLIENT = 4,
    EVENT_SQL_CLIENT = 5,
    EVENT_K_HTTP_REQUEST = 6,
    EVENT_K_HTTP2_REQUEST = 7,
    EVENT_TCP_REQUEST = 8,
    EVENT_GO_KAFKA = 9,
    EVENT_GO_REDIS = 10,
    EVENT_GO_KAFKA_SEG = 11, // the segment-io version (kafka-go) has different format
    EVENT_TCP_LARGE_BUFFER = 12,
    EVENT_GO_SPAN = 13,
    EVENT_GO_MONGO = 14,
    EVENT_FAILED_CONNECT = 15,
    EVENT_DNS_REQUEST = 16,
    EVENT_GO_RUNTIME_METRICS = 17,
    EVENT_GO_CHANNEL_LINK = 18,
    EVENT_JVM_MEM_POOL_GC = 19,
    EVENT_GO_AUTO_SPAN = 20,
    EVENT_GO_RUNTIME_HISTOGRAM = 21,
    EVENT_GO_AUTO_ACTIVATED = 22,
    EVENT_NODEJS_EVENTLOOP = 23,
    EVENT_NODE_SPAN = 24,
    EVENT_K_HTTP2_REQUEST_HEADERS = 25,
    EVENT_K_HTTP2_RESPONSE_HEADERS = 26,
    EVENT_NODEJS_GC = 27,
    EVENT_NODEJS_HEAP_SPACE = 28,
    EVENT_PYTHON_RUNTIME_METRICS = 29,
    EVENT_JVM_RUNTIME_METRICS = 30,
};
