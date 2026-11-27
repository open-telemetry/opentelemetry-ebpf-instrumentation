// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func method091(classID, methodID uint16, args ...[]byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, classID)
	b = binary.BigEndian.AppendUint16(b, methodID)
	for _, a := range args {
		b = append(b, a...)
	}
	return b
}

func shortStr091(s string) []byte {
	return append([]byte{byte(len(s))}, s...)
}

func delivery091(tag uint64) []byte {
	return append(binary.BigEndian.AppendUint64(nil, tag), 0)
}

func TestParseMethod091(t *testing.T) {
	ticket := []byte{0, 0}
	bits := []byte{0}
	messageCount := []byte{0, 0, 0, 3}

	tests := []struct {
		name    string
		payload []byte
		want    Message091
	}{
		{
			name:    "publish",
			payload: method091(classBasic091, methodPublish091, ticket, shortStr091("logs"), shortStr091("warning"), bits),
			want:    Message091{Operation: Publish091, Exchange: "logs", RoutingKey: "warning"},
		},
		{
			name:    "publish to the default exchange",
			payload: method091(classBasic091, methodPublish091, ticket, shortStr091(""), shortStr091("tasks"), bits),
			want:    Message091{Operation: Publish091, RoutingKey: "tasks"},
		},
		{
			name: "deliver",
			payload: method091(classBasic091, methodDeliver091, shortStr091("ctag1.0"), delivery091(7),
				shortStr091("logs"), shortStr091("warning")),
			want: Message091{Operation: Deliver091, Exchange: "logs", RoutingKey: "warning", DeliveryTag: 7},
		},
		{
			name: "get-ok",
			payload: method091(classBasic091, methodGetOk091, delivery091(2), shortStr091(""),
				shortStr091("tasks"), messageCount),
			want: Message091{Operation: GetOk091, RoutingKey: "tasks", DeliveryTag: 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMethod091(tt.payload)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseMethod091Truncated(t *testing.T) {
	payload := method091(classBasic091, methodPublish091, []byte{0, 0}, shortStr091("logs"), shortStr091("warning"))
	cut := payload[:len(payload)-len("ning")]

	got, err := ParseMethod091(cut)
	require.ErrorIs(t, err, errTruncated091)
	assert.Equal(t, Message091{Operation: Publish091, Exchange: "logs", RoutingKey: "war"}, got)

	got, err = ParseMethod091(method091(classBasic091, methodDeliver091, shortStr091("ctag")))
	require.ErrorIs(t, err, errTruncated091)
	assert.Equal(t, Deliver091, got.Operation)
}

func TestParseMethod091TruncatedInsideCharacter(t *testing.T) {
	for name, tt := range map[string]struct {
		routingKey string
		cut        int
		want       string
	}{
		"two-byte character":   {routingKey: "café.créé", cut: len("café.cr") + 1, want: "café.cr"},
		"four-byte character":  {routingKey: "order.🚚", cut: len("order.") + 3, want: "order."},
		"after a character":    {routingKey: "café.créé", cut: len("café"), want: "café"},
		"inside the first one": {routingKey: "é", cut: 1, want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			payload := method091(classBasic091, methodPublish091, []byte{0, 0}, shortStr091(""), shortStr091(tt.routingKey))
			keyStart := len(payload) - len(tt.routingKey)

			got, err := ParseMethod091(payload[:keyStart+tt.cut])
			require.ErrorIs(t, err, errTruncated091)
			assert.Equal(t, tt.want, got.RoutingKey)
		})
	}
}

func TestParseMethod091NotAMessage(t *testing.T) {
	const classChannel, methodAck, methodOpen = 20, 80, 10

	for name, payload := range map[string][]byte{
		"empty":        nil,
		"class only":   {0, classBasic091},
		"basic.ack":    method091(classBasic091, methodAck, delivery091(1)),
		"channel.open": method091(classChannel, methodOpen, shortStr091("")),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseMethod091(payload)
			require.ErrorIs(t, err, ErrNotMessage091)
		})
	}
}
