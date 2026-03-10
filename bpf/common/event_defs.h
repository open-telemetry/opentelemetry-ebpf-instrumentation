// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// These need to line up with some Go identifiers:
// EventTypeHTTP, EventTypeGRPC, EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient, EventTypeKHTTPRequest
#define EVENT_HTTP_REQUEST 1
#define EVENT_GRPC_REQUEST 2
#define EVENT_HTTP_CLIENT 3
#define EVENT_GRPC_CLIENT 4
#define EVENT_SQL_CLIENT 5
#define EVENT_K_HTTP_REQUEST 6
#define EVENT_K_HTTP2_REQUEST 7
#define EVENT_TCP_REQUEST 8
#define EVENT_GO_KAFKA 9
#define EVENT_GO_REDIS 10
#define EVENT_GO_KAFKA_SEG 11 // the segment-io version (kafka-go) has different format
#define EVENT_TCP_LARGE_BUFFER 12
#define EVENT_GO_SPAN 13
#define EVENT_GO_MONGO 14
#define EVENT_FAILED_CONNECT 15
#define EVENT_DNS_REQUEST 16
