// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import "go.opentelemetry.io/obi/pkg/export/instrumentations"

type protocolMapping struct {
	name           string
	instr          instrumentations.Instrumentation
	appMetrics     bool
	metricWildcard bool
}

var protocolMappings = []protocolMapping{
	{name: "http", instr: instrumentations.InstrumentationHTTP, appMetrics: true, metricWildcard: true},
	{name: "grpc", instr: instrumentations.InstrumentationGRPC, appMetrics: true, metricWildcard: true},
	{name: "sql", instr: instrumentations.InstrumentationSQL, appMetrics: true, metricWildcard: true},
	{name: "redis", instr: instrumentations.InstrumentationRedis, appMetrics: true, metricWildcard: true},
	{name: "kafka", instr: instrumentations.InstrumentationKafka, appMetrics: true, metricWildcard: true},
	{name: "mongo", instr: instrumentations.InstrumentationMongo, appMetrics: true, metricWildcard: true},
	{name: "couchbase", instr: instrumentations.InstrumentationCouchbase, appMetrics: true, metricWildcard: true},
	{name: "dns", instr: instrumentations.InstrumentationDNS, appMetrics: false},
	{name: "gpu", instr: instrumentations.InstrumentationGPU, appMetrics: true, metricWildcard: true},
}
