// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
)

func TestRecordGettersWithPortGuessMode_OrdinalUnknownInitiator(t *testing.T) {
	record := &Record{
		NetFlowRecordT: NetFlowRecordT{
			Id: NetFlowId{
				SrcPort: 45678,
				DstPort: 8080,
			},
		},
	}

	cfg := RecordGettersConfig{PortGuessPolicy: flowdef.PortGuessOrdinal}

	clientGetter, ok := RecordStringGetters(cfg)(attr.ClientPort)
	require.True(t, ok)
	serverGetter, ok := RecordStringGetters(cfg)(attr.ServerPort)
	require.True(t, ok)

	assert.Equal(t, "45678", clientGetter(record))
	assert.Equal(t, "8080", serverGetter(record))
}

func TestRecordGettersWithPortGuessMode_DisableUnknownInitiator(t *testing.T) {
	record := &Record{
		NetFlowRecordT: NetFlowRecordT{
			Id: NetFlowId{
				SrcPort: 45678,
				DstPort: 8080,
			},
		},
	}

	cfg := RecordGettersConfig{PortGuessPolicy: flowdef.PortGuessDisable}

	clientGetter, ok := RecordStringGetters(cfg)(attr.ClientPort)
	require.True(t, ok)
	serverGetter, ok := RecordStringGetters(cfg)(attr.ServerPort)
	require.True(t, ok)
	netProtocolGetter, ok := RecordStringGetters(cfg)(attr.NetworkProtocol)
	require.True(t, ok)

	assert.Equal(t, "0", clientGetter(record))
	assert.Equal(t, "0", serverGetter(record))
	assert.Equal(t, "undefined", netProtocolGetter(record))
}

func TestRecordGettersWithPortGuessMode_DisableKnownInitiator(t *testing.T) {
	record := &Record{
		NetFlowRecordT: NetFlowRecordT{
			Id: NetFlowId{
				SrcPort: 45678,
				DstPort: 8080,
			},
			Metrics: NetFlowMetrics{
				Initiator: InitiatorSrc,
			},
		},
	}

	cfg := RecordGettersConfig{PortGuessPolicy: flowdef.PortGuessOrdinal}
	clientGetter, ok := RecordStringGetters(cfg)(attr.ClientPort)
	require.True(t, ok)
	serverGetter, ok := RecordStringGetters(cfg)(attr.ServerPort)
	require.True(t, ok)

	assert.Equal(t, "45678", clientGetter(record))
	assert.Equal(t, "8080", serverGetter(record))
}
