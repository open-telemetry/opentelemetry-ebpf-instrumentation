// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestParseNATSFrame(t *testing.T) {
	header := []byte("NATS/1.0\r\nX-Test: one\r\n\r\n")
	payload := []byte("hello")
	hdrLen := len(header)
	totalLen := hdrLen + len(payload)

	tests := []struct {
		name         string
		frame        []byte
		expectedInfo *NATSInfo
		expectedID   string
		isNATSFrame  bool
		expectErr    bool
	}{
		{
			name:         "PUB",
			frame:        []byte("PUB updates.orders 5\r\nhello\r\n"),
			expectedInfo: &NATSInfo{Operation: request.MessagingPublish, Subject: "updates.orders", PayloadSize: 5},
			isNATSFrame:  true,
		},
		{
			name:         "PUB with reply subject",
			frame:        []byte("PUB updates.orders _INBOX.reply 5\r\nhello\r\n"),
			expectedInfo: &NATSInfo{Operation: request.MessagingPublish, Subject: "updates.orders", PayloadSize: 5},
			isNATSFrame:  true,
		},
		{
			name:         "HPUB",
			frame:        []byte(fmt.Sprintf("HPUB updates.orders %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)),
			expectedInfo: &NATSInfo{Operation: request.MessagingPublish, Subject: "updates.orders", PayloadSize: totalLen},
			isNATSFrame:  true,
		},
		{
			name:         "HPUB with reply subject",
			frame:        []byte(fmt.Sprintf("HPUB updates.orders _INBOX.reply %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)),
			expectedInfo: &NATSInfo{Operation: request.MessagingPublish, Subject: "updates.orders", PayloadSize: totalLen},
			isNATSFrame:  true,
		},
		{
			name:         "MSG with alphanumeric sid",
			frame:        []byte("MSG updates.orders subA 5\r\nhello\r\n"),
			expectedInfo: &NATSInfo{Operation: request.MessagingProcess, Subject: "updates.orders", PayloadSize: 5},
			isNATSFrame:  true,
		},
		{
			name:         "MSG with reply subject",
			frame:        []byte("MSG updates.orders subA _INBOX.reply 5\r\nhello\r\n"),
			expectedInfo: &NATSInfo{Operation: request.MessagingProcess, Subject: "updates.orders", PayloadSize: 5},
			isNATSFrame:  true,
		},
		{
			name:         "HMSG with alphanumeric sid",
			frame:        []byte(fmt.Sprintf("HMSG updates.orders subA %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)),
			expectedInfo: &NATSInfo{Operation: request.MessagingProcess, Subject: "updates.orders", PayloadSize: totalLen},
			isNATSFrame:  true,
		},
		{
			name:         "HMSG with reply subject",
			frame:        []byte(fmt.Sprintf("HMSG updates.orders subA _INBOX.reply %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)),
			expectedInfo: &NATSInfo{Operation: request.MessagingProcess, Subject: "updates.orders", PayloadSize: totalLen},
			isNATSFrame:  true,
		},
		{
			name:      "SUB with too few fields",
			frame:     []byte("SUB updates.orders\r\n"),
			expectErr: true,
		},
		{
			name:      "SUB with too many fields",
			frame:     []byte("SUB updates.orders queue subA extra\r\n"),
			expectErr: true,
		},
		{
			name:      "UNSUB with too few fields",
			frame:     []byte("UNSUB\r\n"),
			expectErr: true,
		},
		{
			name:      "UNSUB with too many fields",
			frame:     []byte("UNSUB subA 1 extra\r\n"),
			expectErr: true,
		},
		{
			name:      "MSG with too few fields",
			frame:     []byte("MSG updates.orders subA\r\n"),
			expectErr: true,
		},
		{
			name:      "MSG with too many fields",
			frame:     []byte("MSG updates.orders subA _INBOX.reply 5 extra\r\nhello\r\n"),
			expectErr: true,
		},
		{
			name:      "HMSG with too few fields",
			frame:     []byte(fmt.Sprintf("HMSG updates.orders subA %d\r\n%s%s\r\n", hdrLen, header, payload)),
			expectErr: true,
		},
		{
			name:      "HMSG with too many fields",
			frame:     []byte(fmt.Sprintf("HMSG updates.orders subA _INBOX.reply %d %d extra\r\n%s%s\r\n", hdrLen, totalLen, header, payload)),
			expectErr: true,
		},
		{
			name:        "CONNECT with client name",
			frame:       []byte(`CONNECT {"verbose":false,"name":"my-service","lang":"go"}` + "\r\n"),
			expectedID:  "my-service",
			isNATSFrame: true,
		},
		{
			name:        "Control frame is weak heuristic",
			frame:       []byte("PING\r\n"),
			isNATSFrame: false,
		},
		{
			name:      "HTTP CONNECT is rejected",
			frame:     []byte("CONNECT proxy.example:443 HTTP/1.1\r\n"),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := largebuf.NewLargeBufferFrom(tt.frame)
			reader := buffer.NewReader()

			frame, err := parseNATSFrame(&reader)
			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedInfo, frame.info)
			assert.Equal(t, tt.expectedID, frame.clientID)
			assert.Equal(t, tt.isNATSFrame, frame.valid)
			assert.Equal(t, len(tt.frame), reader.ReadOffset())
		})
	}
}

func TestProcessNATSEvent(t *testing.T) {
	goConnect := []byte("CONNECT {\"verbose\":false,\"pedantic\":false,\"name\":\"go-client\",\"lang\":\"go\",\"version\":\"1.50.0\",\"protocol\":1,\"headers\":true,\"no_responders\":true}\r\n")
	pythonConnect := []byte("CONNECT {\"echo\": true, \"headers\": true, \"lang\": \"python3\", \"no_responders\": true, \"pedantic\": false, \"protocol\": 1, \"verbose\": false, \"version\": \"2.14.0\"}\r\n")
	header := []byte("NATS/1.0\r\nX-Test: one\r\n\r\n")
	payload := []byte("hello")

	tests := []struct {
		name     string
		packet   *largebuf.LargeBuffer
		expected *NATSInfo
		ignore   bool
		err      bool
	}{
		{
			name:     "Go CONNECT followed by PUB propagates client ID",
			packet:   largebuf.NewLargeBufferFrom(append(goConnect, []byte("PUB updates.orders 5\r\nhello\r\n")...)),
			expected: &NATSInfo{Operation: request.MessagingPublish, Subject: "updates.orders", ClientID: "go-client", PayloadSize: 5},
		},
		{
			name: "Python CONNECT followed by HPUB in multiple chunks",
			packet: newLargeBufferFromChunks(
				pythonConnect,
				fmt.Appendf(nil, "HPUB updates.orders %d %d\r\n%s%s\r\n", len(header), len(header)+len(payload), header, payload),
			),
			expected: &NATSInfo{Operation: request.MessagingPublish, Subject: "updates.orders", PayloadSize: len(header) + len(payload)},
		},
		{
			name:   "Control-only buffer is ignored",
			packet: largebuf.NewLargeBufferFrom(append(goConnect, []byte("PING\r\nPONG\r\n")...)),
			ignore: true,
		},
		{
			name:   "Invalid frame",
			packet: largebuf.NewLargeBufferFrom([]byte("PUB updates.orders 5\r\nhel")),
			err:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, ignore, err := ProcessNATSEvent(tt.packet)
			if tt.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.ignore, ignore)
			assert.Equal(t, tt.expected, info)
		})
	}
}

func TestParseNATSPayloadFields(t *testing.T) {
	subject, size, err := parseNATSPayloadFields([][]byte{
		[]byte("PUB"), []byte("updates.orders"), []byte("5"),
	})
	require.NoError(t, err)
	assert.Equal(t, "updates.orders", subject)
	assert.Equal(t, 5, size)

	subject, size, err = parseNATSPayloadFields([][]byte{
		[]byte("PUB"), []byte("updates.orders"), []byte("_INBOX.reply"), []byte("5"),
	})
	require.NoError(t, err)
	assert.Equal(t, "updates.orders", subject)
	assert.Equal(t, 5, size)

	_, _, err = parseNATSPayloadFields([][]byte{
		[]byte("PUB"), []byte("updates.orders"),
	})
	require.Error(t, err)

	_, _, err = parseNATSPayloadFields([][]byte{
		[]byte("PUB"), []byte("updates.orders"), []byte("reply"), []byte("5"), []byte("extra"),
	})
	require.Error(t, err)

	_, _, err = parseNATSPayloadFields([][]byte{
		[]byte("PUB"), []byte("updates.orders"), []byte("notanint"),
	})
	require.Error(t, err)
}

func TestParseNATSHeaderPayloadFields(t *testing.T) {
	subject, size, err := parseNATSHeaderPayloadFields([][]byte{
		[]byte("HPUB"), []byte("updates.orders"), []byte("26"), []byte("31"),
	})
	require.NoError(t, err)
	assert.Equal(t, "updates.orders", subject)
	assert.Equal(t, 31, size)

	subject, size, err = parseNATSHeaderPayloadFields([][]byte{
		[]byte("HPUB"), []byte("updates.orders"), []byte("_INBOX.reply"), []byte("26"), []byte("31"),
	})
	require.NoError(t, err)
	assert.Equal(t, "updates.orders", subject)
	assert.Equal(t, 31, size)

	_, _, err = parseNATSHeaderPayloadFields([][]byte{
		[]byte("HPUB"), []byte("updates.orders"), []byte("31"),
	})
	require.Error(t, err)

	_, _, err = parseNATSHeaderPayloadFields([][]byte{
		[]byte("HPUB"), []byte("updates.orders"), []byte("reply"), []byte("26"), []byte("31"), []byte("extra"),
	})
	require.Error(t, err)

	_, _, err = parseNATSHeaderPayloadFields([][]byte{
		[]byte("HPUB"), []byte("updates.orders"), []byte("40"), []byte("31"),
	})
	require.Error(t, err)
}

func TestConsumeNATSPayload(t *testing.T) {
	buffer := largebuf.NewLargeBufferFrom([]byte("hello\r\n"))
	reader := buffer.NewReader()
	require.NoError(t, consumeNATSPayload(&reader, 5))

	buffer = largebuf.NewLargeBufferFrom([]byte("hello"))
	reader = buffer.NewReader()
	require.Error(t, consumeNATSPayload(&reader, 5))

	buffer = largebuf.NewLargeBufferFrom([]byte("hello\r\n"))
	reader = buffer.NewReader()
	require.Error(t, consumeNATSPayload(&reader, -1))
}

func TestProcessPossibleNATSEvent(t *testing.T) {
	t.Run("span found in response direction triggers reversal", func(t *testing.T) {
		event := makeTCPReq("", 4222)
		requestBuf := largebuf.NewLargeBufferFrom([]byte("PING\r\n"))
		responseBuf := largebuf.NewLargeBufferFrom([]byte("MSG updates.orders sidA 5\r\nhello\r\n"))

		info, extraInfo, ignore, err := ProcessPossibleNATSEvent(&event, requestBuf, responseBuf)
		require.NoError(t, err)
		assert.False(t, ignore)
		assert.Equal(t, &NATSInfo{Operation: request.MessagingProcess, Subject: "updates.orders", PayloadSize: 5}, info)
		assert.Nil(t, extraInfo)
		assert.Equal(t, uint8(directionRecv), event.Direction)
	})

	t.Run("span found in request direction - no reversal", func(t *testing.T) {
		event := makeTCPReq("", 4222)
		originalDirection := event.Direction
		requestBuf := largebuf.NewLargeBufferFrom([]byte("PUB updates.orders 5\r\nhello\r\n"))
		responseBuf := largebuf.NewLargeBufferFrom([]byte("PONG\r\n"))

		info, extraInfo, ignore, err := ProcessPossibleNATSEvent(&event, requestBuf, responseBuf)
		require.NoError(t, err)
		assert.False(t, ignore)
		assert.Equal(t, &NATSInfo{Operation: request.MessagingPublish, Subject: "updates.orders", PayloadSize: 5}, info)
		assert.Nil(t, extraInfo)
		assert.Equal(t, originalDirection, event.Direction) // direction must not change
	})

	t.Run("both buffers have span-worthy frames", func(t *testing.T) {
		event := makeTCPReq("", 4222)
		originalDirection := event.Direction

		header := "NATS/1.0\r\nX-Test: python\r\n\r\n"
		payload := "python-nats-1"
		hdrLen := len(header)
		totalLen := hdrLen + len(payload)

		requestBuf := largebuf.NewLargeBufferFrom(
			[]byte(fmt.Sprintf("HPUB updates.orders %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)),
		)
		responseBuf := largebuf.NewLargeBufferFrom(
			[]byte(fmt.Sprintf("HMSG updates.orders subA %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)),
		)

		info, extraInfo, ignore, err := ProcessPossibleNATSEvent(&event, requestBuf, responseBuf)
		require.NoError(t, err)
		assert.False(t, ignore)
		assert.Equal(t, request.MessagingPublish, info.Operation)
		assert.Equal(t, "updates.orders", info.Subject)
		assert.Equal(t, totalLen, info.PayloadSize)
		require.NotNil(t, extraInfo)
		assert.Equal(t, request.MessagingProcess, extraInfo.Operation)
		assert.Equal(t, "updates.orders", extraInfo.Subject)
		assert.Equal(t, totalLen, extraInfo.PayloadSize)
		assert.Equal(t, originalDirection, event.Direction) // no reversal
	})

	t.Run("reversed coalesced publish and process keeps publish as primary span", func(t *testing.T) {
		event := makeTCPReq("", 4222)
		originalDirection := event.Direction

		header := "NATS/1.0\r\nX-Test: python\r\n\r\n"
		payload := "python-nats-1"
		hdrLen := len(header)
		totalLen := hdrLen + len(payload)

		requestBuf := largebuf.NewLargeBufferFrom(
			[]byte(fmt.Sprintf("HMSG updates.orders subA %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)),
		)
		responseBuf := largebuf.NewLargeBufferFrom(
			[]byte(fmt.Sprintf("HPUB updates.orders %d %d\r\n%s%s\r\n", hdrLen, totalLen, header, payload)),
		)

		info, extraInfo, ignore, err := ProcessPossibleNATSEvent(&event, requestBuf, responseBuf)
		require.NoError(t, err)
		assert.False(t, ignore)
		require.NotNil(t, info)
		require.NotNil(t, extraInfo)
		assert.Equal(t, request.MessagingPublish, info.Operation)
		assert.Equal(t, request.MessagingProcess, extraInfo.Operation)
		assert.Equal(t, originalDirection, event.Direction)
	})

	t.Run("control-only in both directions - valid NATS, no span", func(t *testing.T) {
		event := makeTCPReq("", 4222)
		requestBuf := largebuf.NewLargeBufferFrom([]byte("PING\r\n"))
		responseBuf := largebuf.NewLargeBufferFrom([]byte("PONG\r\n"))

		info, extraInfo, ignore, err := ProcessPossibleNATSEvent(&event, requestBuf, responseBuf)
		require.NoError(t, err)
		assert.True(t, ignore)
		assert.Nil(t, info)
		assert.Nil(t, extraInfo)
	})

	t.Run("both directions fail - error returned", func(t *testing.T) {
		event := makeTCPReq("", 4222)
		requestBuf := largebuf.NewLargeBufferFrom([]byte("NOT NATS DATA\r\n"))
		responseBuf := largebuf.NewLargeBufferFrom([]byte("ALSO NOT NATS\r\n"))

		info, extraInfo, ignore, err := ProcessPossibleNATSEvent(&event, requestBuf, responseBuf)
		require.Error(t, err)
		assert.True(t, ignore)
		assert.Nil(t, info)
		assert.Nil(t, extraInfo)
	})
}

func TestTCPToNATSToSpan(t *testing.T) {
	event := makeTCPReq("", 4222)

	span := TCPToNATSToSpan(&event, &NATSInfo{
		Operation:   request.MessagingPublish,
		Subject:     "updates.orders",
		ClientID:    "my-service",
		PayloadSize: 42,
	})
	assert.Equal(t, request.EventTypeNATSClient, span.Type)
	assert.Equal(t, request.MessagingPublish, span.Method)
	assert.Equal(t, "updates.orders", span.Path)
	assert.Equal(t, "my-service", span.Statement)
	assert.Equal(t, int64(42), span.ContentLength)
	assert.Equal(t, 8080, span.HostPort)
}

func newLargeBufferFromChunks(chunks ...[]byte) *largebuf.LargeBuffer {
	buffer := largebuf.NewLargeBuffer()
	for _, chunk := range chunks {
		buffer.AppendChunk(chunk)
	}

	return buffer
}
