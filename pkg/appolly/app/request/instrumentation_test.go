// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

func TestEventTypeInstrumentation(t *testing.T) {
	tests := map[instrumentations.Instrumentation][]EventType{
		instrumentations.InstrumentationHTTP:      {EventTypeHTTP, EventTypeHTTPClient},
		instrumentations.InstrumentationGRPC:      {EventTypeGRPC, EventTypeGRPCClient},
		instrumentations.InstrumentationSQL:       {EventTypeSQLClient, EventTypeSQLServer},
		instrumentations.InstrumentationRedis:     {EventTypeRedisClient, EventTypeRedisServer},
		instrumentations.InstrumentationKafka:     {EventTypeKafkaClient, EventTypeKafkaServer},
		instrumentations.InstrumentationMQTT:      {EventTypeMQTTClient, EventTypeMQTTServer},
		instrumentations.InstrumentationNATS:      {EventTypeNATSClient, EventTypeNATSServer},
		instrumentations.InstrumentationAMQP:      {EventTypeAMQPClient},
		instrumentations.InstrumentationGPU:       {EventTypeGPUCudaKernelLaunch, EventTypeGPUCudaGraphLaunch, EventTypeGPUCudaMalloc, EventTypeGPUCudaMemcpy},
		instrumentations.InstrumentationMongo:     {EventTypeMongoClient},
		instrumentations.InstrumentationDNS:       {EventTypeDNS},
		instrumentations.InstrumentationCouchbase: {EventTypeCouchbaseClient},
		instrumentations.InstrumentationMemcached: {EventTypeMemcachedClient, EventTypeMemcachedServer},
		instrumentations.InstrumentationSunRPC:    {EventTypeSunRPCClient, EventTypeSunRPCServer},
		instrumentations.InstrumentationAerospike: {EventTypeAerospikeClient},
	}

	for want, eventTypes := range tests {
		for _, eventType := range eventTypes {
			got, ok := eventType.Instrumentation()
			assert.True(t, ok, eventType)
			assert.Equal(t, want, got, eventType)
		}
	}

	for _, eventType := range []EventType{
		EventTypeProcessAlive,
		EventTypeManualSpan,
		EventTypeFailedConnect,
		EventType(255),
	} {
		_, ok := eventType.Instrumentation()
		assert.False(t, ok, eventType)
	}
}
