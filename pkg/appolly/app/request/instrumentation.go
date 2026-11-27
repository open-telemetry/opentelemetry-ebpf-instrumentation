// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import "go.opentelemetry.io/obi/pkg/export/instrumentations"

// IgnoreMetricsFor applies the exporter's protocol selection to ISO 8583,
// including derived metrics. Older protocols retain the v1 derived metric behavior.
func IgnoreMetricsFor(s *Span, selection instrumentations.InstrumentationSelection) bool {
	if IgnoreMetrics(s) {
		return true
	}
	switch s.Type {
	case EventTypeISO8583Client, EventTypeISO8583Server:
		return !selection.ISO8583Enabled()
	default:
		return false
	}
}

// Instrumentation returns the instrumentation that produced the event type.
func (t EventType) Instrumentation() (instrumentations.Instrumentation, bool) {
	switch t {
	case EventTypeHTTP, EventTypeHTTPClient:
		return instrumentations.InstrumentationHTTP, true
	case EventTypeGRPC, EventTypeGRPCClient:
		return instrumentations.InstrumentationGRPC, true
	case EventTypeSQLClient, EventTypeSQLServer:
		return instrumentations.InstrumentationSQL, true
	case EventTypeRedisClient, EventTypeRedisServer:
		return instrumentations.InstrumentationRedis, true
	case EventTypeKafkaClient, EventTypeKafkaServer:
		return instrumentations.InstrumentationKafka, true
	case EventTypeMQTTClient, EventTypeMQTTServer:
		return instrumentations.InstrumentationMQTT, true
	case EventTypeNATSClient, EventTypeNATSServer:
		return instrumentations.InstrumentationNATS, true
	case EventTypeAMQPClient:
		return instrumentations.InstrumentationAMQP, true
	case EventTypeGPUCudaKernelLaunch, EventTypeGPUCudaGraphLaunch, EventTypeGPUCudaMalloc,
		EventTypeGPUCudaMemcpy, EventTypeGPUCudaFree, EventTypeGPUCudaMemset,
		EventTypeGPUCudaStreamCreate, EventTypeGPUCudaStreamDestroy, EventTypeGPUCudaEventRecord,
		EventTypeGPUCudaEventSynchronize, EventTypeGPUCudaStreamSynchronize,
		EventTypeGPUCudaDeviceSynchronize, EventTypeGPUCudaHostRegister:
		return instrumentations.InstrumentationGPU, true
	case EventTypeMongoClient:
		return instrumentations.InstrumentationMongo, true
	case EventTypeDNS:
		return instrumentations.InstrumentationDNS, true
	case EventTypeCouchbaseClient:
		return instrumentations.InstrumentationCouchbase, true
	case EventTypeMemcachedClient, EventTypeMemcachedServer:
		return instrumentations.InstrumentationMemcached, true
	case EventTypeSunRPCClient, EventTypeSunRPCServer:
		return instrumentations.InstrumentationSunRPC, true
	case EventTypeAerospikeClient, EventTypeAerospikeServer:
		return instrumentations.InstrumentationAerospike, true
	case EventTypeISO8583Client, EventTypeISO8583Server:
		return instrumentations.InstrumentationISO8583, true
	default:
		return "", false
	}
}
