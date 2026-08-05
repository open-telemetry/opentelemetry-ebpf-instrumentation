// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestGoKafkaSaramaToSpanPropagatesTraceContext(t *testing.T) {
	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	spanID := trace.SpanID{17, 18, 19, 20, 21, 22, 23, 24}
	parentSpanID := trace.SpanID{25, 26, 27, 28, 29, 30, 31, 32}
	event := GoSaramaClientInfo{}
	copy(event.Tp.TraceId[:], traceID[:])
	copy(event.Tp.SpanId[:], spanID[:])
	copy(event.Tp.ParentId[:], parentSpanID[:])
	event.Tp.Flags = TPFlagRandom
	event.Tp.ParentRemote = 1
	event.Tp.SamplingDecision = 1

	span := GoKafkaSaramaToSpan(&event, &KafkaInfo{
		Operation: Produce,
		Topic:     "test-topic",
		ClientID:  "sarama",
	})

	assert.Equal(t, traceID, span.TraceID)
	assert.Equal(t, spanID, span.SpanID)
	assert.Equal(t, parentSpanID, span.ParentSpanID)
	assert.Equal(t, uint8(TPFlagRandom), span.TraceFlags)
	assert.True(t, span.ParentRemote)
	assert.True(t, span.BPFDecision)
}

func TestReadGoKafkaGoRequestIntoSpanOperation(t *testing.T) {
	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	spanID := trace.SpanID{17, 18, 19, 20, 21, 22, 23, 24}
	parentSpanID := trace.SpanID{25, 26, 27, 28, 29, 30, 31, 32}
	tests := []struct {
		name     string
		apiKey   uint8
		method   string
		spanKind string
	}{
		{
			name:     "fetch",
			apiKey:   kafkaGoAPIFetch,
			method:   request.MessagingProcess,
			spanKind: "SPAN_KIND_CONSUMER",
		},
		{
			name:     "produce",
			apiKey:   kafkaGoAPIProduce,
			method:   request.MessagingPublish,
			spanKind: "SPAN_KIND_PRODUCER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := GoKafkaGoClientInfo{Op: tt.apiKey}
			copy(event.Tp.TraceId[:], traceID[:])
			copy(event.Tp.SpanId[:], spanID[:])
			copy(event.Tp.ParentId[:], parentSpanID[:])
			event.Tp.Flags = TPFlagRandom
			event.Tp.ParentRemote = 1
			event.Tp.SamplingDecision = 1
			copy(event.Topic[:], "test-topic")

			var raw bytes.Buffer
			require.NoError(t, binary.Write(&raw, binary.LittleEndian, event))

			span, ignore, err := ReadGoKafkaGoRequestIntoSpan(&ringbuf.Record{RawSample: raw.Bytes()})

			require.NoError(t, err)
			assert.False(t, ignore)
			assert.Equal(t, request.EventTypeKafkaClient, span.Type)
			assert.Equal(t, "github.com/segmentio/kafka-go", span.Statement)
			assert.Equal(t, tt.method, span.Method)
			assert.Equal(t, "test-topic", span.Path)
			assert.Equal(t, tt.method+" test-topic", span.TraceName())
			assert.Equal(t, tt.spanKind, span.ServiceGraphKind())
			assert.Equal(t, traceID, span.TraceID)
			assert.Equal(t, spanID, span.SpanID)
			assert.Equal(t, parentSpanID, span.ParentSpanID)
			assert.Equal(t, uint8(TPFlagRandom), span.TraceFlags)
			assert.True(t, span.ParentRemote)
			assert.True(t, span.BPFDecision)
		})
	}
}
