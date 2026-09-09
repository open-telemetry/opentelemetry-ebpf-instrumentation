// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

// These must line up with the EventType* constants in pkg/ebpf/common/common.go.
enum event_type : u8 {
    k_event_type_http_request = 1,
    k_event_type_grpc_request = 2,
    k_event_type_http_client = 3,
    k_event_type_grpc_client = 4,
    k_event_type_sql_client = 5,
    k_event_type_k_http_request = 6,
    k_event_type_k_http2_request = 7,
    k_event_type_tcp_request = 8,
    k_event_type_go_kafka = 9,
    k_event_type_go_redis = 10,
    k_event_type_go_kafka_seg = 11, // the segment-io version (kafka-go) has different format
    k_event_type_tcp_large_buffer = 12,
    k_event_type_go_span = 13,
    k_event_type_go_mongo = 14,
    k_event_type_failed_connect = 15,
    k_event_type_dns_request = 16,
    k_event_type_go_runtime_metrics = 17,
    k_event_type_go_channel_link = 18,
    k_event_type_jvm_mem_pool_gc = 19,
    k_event_type_go_auto_span = 20,
    k_event_type_go_runtime_histogram = 21,
    k_event_type_go_auto_activated = 22,
    k_event_type_nodejs_eventloop = 23,
    k_event_type_node_span = 24,
    k_event_type_k_http2_request_headers = 25,
    k_event_type_k_http2_response_headers = 26,
    k_event_type_nodejs_gc = 27,
    k_event_type_nodejs_heap_space = 28,
    k_event_type_python_runtime_metrics = 29,
    k_event_type_jvm_runtime_metrics = 30,
    k_event_type_nodejs_resource = 31,
};
