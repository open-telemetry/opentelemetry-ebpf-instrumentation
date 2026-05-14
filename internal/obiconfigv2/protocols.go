// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obiconfigv2 // import "go.opentelemetry.io/obi/internal/obiconfigv2"

import "go.opentelemetry.io/obi/pkg/export/instrumentations"

type protocolMapping struct {
	name       string
	instr      instrumentations.Instrumentation
	appMetrics bool
}

var runtimeInstrumentations = []instrumentations.Instrumentation{
	instrumentations.InstrumentationHTTP,
	instrumentations.InstrumentationGRPC,
	instrumentations.InstrumentationSQL,
	instrumentations.InstrumentationRedis,
	instrumentations.InstrumentationKafka,
	instrumentations.InstrumentationMQTT,
	instrumentations.InstrumentationNATS,
	instrumentations.InstrumentationAMQP,
	instrumentations.InstrumentationGPU,
	instrumentations.InstrumentationMongo,
	instrumentations.InstrumentationDNS,
	instrumentations.InstrumentationCouchbase,
	instrumentations.InstrumentationGenAI,
	instrumentations.InstrumentationMemcached,
}

var protocolMappings = []protocolMapping{
	{name: "http", instr: instrumentations.InstrumentationHTTP, appMetrics: true},
	{name: "grpc", instr: instrumentations.InstrumentationGRPC, appMetrics: true},
	{name: "sql", instr: instrumentations.InstrumentationSQL, appMetrics: true},
	{name: "redis", instr: instrumentations.InstrumentationRedis, appMetrics: true},
	{name: "kafka", instr: instrumentations.InstrumentationKafka, appMetrics: true},
	{name: "mongo", instr: instrumentations.InstrumentationMongo, appMetrics: true},
	{name: "couchbase", instr: instrumentations.InstrumentationCouchbase, appMetrics: true},
	{name: "dns", instr: instrumentations.InstrumentationDNS, appMetrics: false},
	{name: "gpu", instr: instrumentations.InstrumentationGPU, appMetrics: true},
}
