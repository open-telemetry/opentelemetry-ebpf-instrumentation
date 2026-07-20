// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestReadGoKafkaGoRequestIntoSpanOperation(t *testing.T) {
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
		})
	}
}
