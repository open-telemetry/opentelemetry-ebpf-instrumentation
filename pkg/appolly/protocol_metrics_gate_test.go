// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestProtocolMetricsSpanGate(t *testing.T) {
	for _, test := range []struct {
		name       string
		v2         bool
		protocols  []instrumentations.Instrumentation
		ignoreHTTP bool
		ignoreGRPC bool
	}{
		{name: "v1"},
		{name: "v2 grpc", v2: true, protocols: []instrumentations.Instrumentation{instrumentations.InstrumentationGRPC}, ignoreHTTP: true},
		{name: "v2 none", v2: true, ignoreHTTP: true, ignoreGRPC: true},
		{name: "v2 all", v2: true, protocols: []instrumentations.Instrumentation{instrumentations.InstrumentationALL}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			var policy *instrumentations.InstrumentationSelection
			if test.v2 {
				selection := instrumentations.NewInstrumentationSelection(test.protocols)
				policy = &selection
			}
			input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
			output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
			outCh := output.Subscribe()
			run, err := protocolMetricsSpanGate(policy, input, output)(ctx)
			require.NoError(t, err)
			go run(ctx)
			input.Send([]request.Span{
				{Type: request.EventTypeHTTP},
				{Type: request.EventTypeHTTPClient},
				{Type: request.EventTypeGRPC},
				{Type: request.EventTypeManualSpan},
			})
			got := testutil.ReadChannel(t, outCh, gateTestTimeout)
			require.Len(t, got, 4)
			assertSignalIgnores(t, &got[0], false, test.ignoreHTTP)
			assertSignalIgnores(t, &got[1], false, test.ignoreHTTP)
			assertSignalIgnores(t, &got[2], false, test.ignoreGRPC)
			assertSignalIgnores(t, &got[3], false, false)
		})
	}
}
