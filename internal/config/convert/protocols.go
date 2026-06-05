// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import "go.opentelemetry.io/obi/pkg/export/instrumentations"

type protocolMapping struct {
	name       string
	instr      instrumentations.Instrumentation
	appMetrics bool
}

var protocolMappings = []protocolMapping{
	{name: "http", instr: instrumentations.InstrumentationHTTP, appMetrics: true},
	{name: "grpc", instr: instrumentations.InstrumentationGRPC, appMetrics: true},
	{name: "sql", instr: instrumentations.InstrumentationSQL, appMetrics: true},
	{name: "redis", instr: instrumentations.InstrumentationRedis, appMetrics: true},
	{name: "kafka", instr: instrumentations.InstrumentationKafka, appMetrics: true},
	{name: "mqtt", instr: instrumentations.InstrumentationMQTT, appMetrics: true},
	{name: "nats", instr: instrumentations.InstrumentationNATS, appMetrics: true},
	{name: "amqp", instr: instrumentations.InstrumentationAMQP, appMetrics: true},
	{name: "mongo", instr: instrumentations.InstrumentationMongo, appMetrics: true},
	{name: "couchbase", instr: instrumentations.InstrumentationCouchbase, appMetrics: true},
	{name: "memcached", instr: instrumentations.InstrumentationMemcached, appMetrics: true},
	{name: "dns", instr: instrumentations.InstrumentationDNS, appMetrics: false},
	{name: "gpu", instr: instrumentations.InstrumentationGPU, appMetrics: true},
	{name: "genai", instr: instrumentations.InstrumentationGenAI, appMetrics: true},
}
