// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProtocolHeader(t *testing.T) {
	t.Run("protocolIDAMQP happy path", func(t *testing.T) {
		h, err := parseProtocolHeader(newLargeBufferReader(makeProtocolHeader(protocolIDAMQP)))
		require.NoError(t, err)
		assert.Equal(t, protocolIDAMQP, h.ID)
		assert.EqualValues(t, 1, h.Major)
		assert.EqualValues(t, 0, h.Minor)
		assert.EqualValues(t, 0, h.Revision)
	})

	t.Run("protocolIDAMQPTLS is accepted", func(t *testing.T) {
		h, err := parseProtocolHeader(newLargeBufferReader(makeProtocolHeader(protocolIDAMQPTLS)))
		require.NoError(t, err)
		assert.Equal(t, protocolIDAMQPTLS, h.ID)
	})

	t.Run("protocolIDSASL is accepted", func(t *testing.T) {
		h, err := parseProtocolHeader(newLargeBufferReader(makeProtocolHeader(protocolIDSASL)))
		require.NoError(t, err)
		assert.Equal(t, protocolIDSASL, h.ID)
	})

	t.Run("short buffer is rejected", func(t *testing.T) {
		_, err := parseProtocolHeader(newLargeBufferReader([]byte{'A', 'M', 'Q', 'P', 0, 1, 0}))
		require.Error(t, err)
	})

	t.Run("bad magic is rejected", func(t *testing.T) {
		_, err := parseProtocolHeader(newLargeBufferReader([]byte{'H', 'T', 'T', 'P', 0, 1, 0, 0}))
		require.Error(t, err)
	})

	t.Run("invalid protocol id is rejected", func(t *testing.T) {
		for _, id := range []byte{1, 4, 99, 255} {
			bytes := []byte{'A', 'M', 'Q', 'P', id, 1, 0, 0}
			_, err := parseProtocolHeader(newLargeBufferReader(bytes))
			require.Errorf(t, err, "protocol id %d should be rejected", id)
		}
	})

	t.Run("AMQP 0-9-1 handshake bytes are rejected", func(t *testing.T) {
		// 0-9-1 uses version bytes {0, 0, 9, 1}; spec requires {1, 0, 0} for AMQP 1.0.
		_, err := parseProtocolHeader(newLargeBufferReader([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}))
		require.Error(t, err)
	})
}
