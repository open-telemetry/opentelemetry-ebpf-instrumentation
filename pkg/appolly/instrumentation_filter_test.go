// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestInstrumentationFilterSpanGate(t *testing.T) {
	httpPort := 8787
	serverError := 500
	sqlPort := 5432
	config := filter.InstrumentationAttributeFamilyConfig{
		instrumentations.InstrumentationHTTP: {
			Traces: filter.AttributeFamilyConfig{
				"server.port": {Equals: &httpPort},
			},
			Metrics: filter.AttributeFamilyConfig{
				"http.response.status_code": {LessThan: &serverError},
			},
		},
		instrumentations.InstrumentationSQL: {
			Metrics: filter.AttributeFamilyConfig{
				"server.port": {Equals: &sqlPort},
			},
		},
	}

	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	outCh := output.Subscribe()

	runFn, err := InstrumentationFilterSpanGate(
		config,
		nil,
		spanPtrPromGetters(&obi.Config{}),
		input,
		output,
	)(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go runFn(ctx)

	input.Send([]request.Span{
		{Type: request.EventTypeHTTP, HostPort: httpPort, Status: 200},
		{Type: request.EventTypeHTTP, HostPort: 8080, Status: 200},
		{Type: request.EventTypeHTTPClient, HostPort: httpPort, Status: serverError},
		{Type: request.EventTypeSQLClient, HostPort: sqlPort},
		{Type: request.EventTypeSQLClient, HostPort: 3306},
		{Type: request.EventTypeRedisClient, HostPort: 6379},
		{Type: request.EventTypeManualSpan},
	})

	got := testutil.ReadChannel(t, outCh, gateTestTimeout)
	require.Len(t, got, 7)
	assertSignalIgnores(t, &got[0], false, false)
	assertSignalIgnores(t, &got[1], true, false)
	assertSignalIgnores(t, &got[2], false, true)
	assertSignalIgnores(t, &got[3], false, false)
	assertSignalIgnores(t, &got[4], false, true)
	assertSignalIgnores(t, &got[5], false, false)
	assertSignalIgnores(t, &got[6], false, false)
}

func TestInstrumentationFilterSpanGateRejectsInvalidFilter(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))

	_, err := InstrumentationFilterSpanGate(
		filter.InstrumentationAttributeFamilyConfig{
			instrumentations.InstrumentationHTTP: {
				Traces: filter.AttributeFamilyConfig{
					"unknown.attribute": {Match: "value"},
				},
			},
		},
		nil,
		spanPtrPromGetters(&obi.Config{}),
		input,
		output,
	)(t.Context())
	require.ErrorContains(t, err, "http trace filters: attribute filter: unknown attribute name")
}

func assertSignalIgnores(t *testing.T, span *request.Span, traces, metrics bool) {
	t.Helper()
	assert.Equal(t, traces, request.IgnoreTraces(span))
	assert.Equal(t, metrics, request.IgnoreMetrics(span))
}
