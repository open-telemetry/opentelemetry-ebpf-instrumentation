// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestParseContextCloseUnblocksSpanEmission(t *testing.T) {
	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	spans.Subscribe() // never read, so the second send would block forever
	parseCtx := NewEBPFParseContext(nil, spans, nil)
	parseCtx.emitSpans([]request.Span{{Type: request.EventTypeHTTP}})

	parseCtx.Close()

	done := make(chan struct{})
	go func() {
		parseCtx.emitSpans([]request.Span{{Type: request.EventTypeHTTP}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("span emission still blocks after Close")
	}
}
