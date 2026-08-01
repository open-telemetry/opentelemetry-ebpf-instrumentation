// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func encodeHTTP2HeaderBlock(t *testing.T, fields ...hpack.HeaderField) []byte {
	t.Helper()

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range fields {
		require.NoError(t, encoder.WriteField(field))
	}

	return block.Bytes()
}

func makeHTTP2Payload(t *testing.T, preface bool, writeFrames func(*http2.Framer)) []byte {
	t.Helper()

	var payload bytes.Buffer
	if preface {
		payload.WriteString(http2.ClientPreface)
	}

	writeFrames(http2.NewFramer(&payload, nil))
	return payload.Bytes()
}

func largeBufferFromChunks(payload []byte, splitAt ...int) *largebuf.LargeBuffer {
	buffer := largebuf.NewLargeBuffer()
	start := 0
	for _, end := range splitAt {
		buffer.AppendChunk(payload[start:end])
		start = end
	}
	buffer.AppendChunk(payload[start:])

	return buffer
}

func TestLooksLikeHTTP1Request(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   bool
	}{
		{
			name:   "request line",
			chunks: []string{"POST /v1/messages HTTP/1.1\r\nHost: example.com\r\n\r\n"},
			want:   true,
		},
		{
			name:   "marker spans chunks",
			chunks: []string{"GET / HTTP", "/1.1\r\n\r\n"},
			want:   true,
		},
		{
			name:   "marker after request line",
			chunks: []string{"not HTTP\nGET / HTTP/1.1\r\n\r\n"},
			want:   false,
		},
		{
			name:   "marker ends at scan limit",
			chunks: []string{strings.Repeat("x", maxHTTP1RequestLineScan-len(http1RequestLineMarker)) + string(http1RequestLineMarker)},
			want:   true,
		},
		{
			name:   "marker exceeds scan limit",
			chunks: []string{strings.Repeat("x", maxHTTP1RequestLineScan-len(http1RequestLineMarker)+1) + string(http1RequestLineMarker)},
			want:   false,
		},
		{
			name:   "HTTP2 request",
			chunks: []string{"POST /v1/messages HTTP/2.0\r\n"},
			want:   false,
		},
		{
			name: "empty buffer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := largebuf.NewLargeBuffer()
			for _, chunk := range tt.chunks {
				buffer.AppendChunk([]byte(chunk))
			}

			assert.Equal(t, tt.want, looksLikeHTTP1Request(buffer))
		})
	}
}

func TestLooksLikeHTTP1Response(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   bool
	}{
		{
			name:   "response status line",
			chunks: []string{"HTTP/1.1 200 OK\r\n\r\n"},
			want:   true,
		},
		{
			name:   "marker spans chunks",
			chunks: []string{"HTT", "P/1.1 200 OK\r\n\r\n"},
			want:   true,
		},
		{
			name:   "marker is not at start",
			chunks: []string{" HTTP/1.1 200 OK\r\n\r\n"},
			want:   false,
		},
		{
			name:   "HTTP2 response",
			chunks: []string{"HTTP/2.0 200 OK\r\n\r\n"},
			want:   false,
		},
		{
			name:   "short buffer",
			chunks: []string{"HTTP/1"},
			want:   false,
		},
		{
			name: "empty buffer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := largebuf.NewLargeBuffer()
			for _, chunk := range tt.chunks {
				buffer.AppendChunk([]byte(chunk))
			}

			assert.Equal(t, tt.want, looksLikeHTTP1Response(buffer))
		})
	}
}

func TestParseHTTP2Request(t *testing.T) {
	headerBlock := encodeHTTP2HeaderBlock(t,
		hpack.HeaderField{Name: ":method", Value: http.MethodGet},
		hpack.HeaderField{Name: ":path", Value: "/ignored-by-parser"},
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
		hpack.HeaderField{Name: "x-request-id", Value: "request-123"},
		hpack.HeaderField{Name: "x-empty", Value: ""},
	)
	payload := makeHTTP2Payload(t, true, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: headerBlock,
			EndHeaders:    true,
		}))
		require.NoError(t, framer.WriteData(1, false, []byte("hello ")))
		require.NoError(t, framer.WriteData(1, true, []byte("world")))
	})
	buffer := largeBufferFromChunks(payload, 2, len(http2.ClientPreface)-1, len(payload)-3)
	span := &request.Span{
		Method: http.MethodPost,
		Host:   "api.example.com",
		Path:   "/v1/messages",
	}

	req, ok := parseHTTP2Request(buffer, span)
	require.True(t, ok)
	require.NotNil(t, req)

	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "HTTP/2.0", req.Proto)
	assert.Equal(t, 2, req.ProtoMajor)
	assert.Zero(t, req.ProtoMinor)
	assert.Equal(t, "api.example.com", req.Host)
	assert.Equal(t, "/v1/messages", req.URL.Path)
	assert.Equal(t, "api.example.com", req.URL.Host)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "request-123", req.Header.Get("X-Request-Id"))
	assert.Empty(t, req.Header.Get(":method"))
	assert.NotContains(t, req.Header, "X-Empty")
	assert.Equal(t, int64(len("hello world")), req.ContentLength)
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello world"), body)
}

func TestParseHTTP2RequestRejectsPayloadWithoutBody(t *testing.T) {
	headerBlock := encodeHTTP2HeaderBlock(t,
		hpack.HeaderField{Name: ":method", Value: http.MethodGet},
		hpack.HeaderField{Name: ":path", Value: "/health"},
	)
	headersOnly := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: headerBlock,
			EndHeaders:    true,
			EndStream:     true,
		}))
	})
	emptyData := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteData(1, true, nil))
	})
	truncatedData := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteData(1, true, []byte("body")))
	})
	truncatedData = truncatedData[:len(truncatedData)-1]

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "empty", payload: nil},
		{name: "headers only", payload: headersOnly},
		{name: "empty DATA frame", payload: emptyData},
		{name: "truncated DATA frame", payload: truncatedData},
		{name: "garbage", payload: []byte("not HTTP/2 frames")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, ok := parseHTTP2Request(largebuf.NewLargeBufferFrom(tt.payload), &request.Span{})

			assert.False(t, ok)
			assert.Nil(t, req)
		})
	}
}

func TestParseHTTP2Response(t *testing.T) {
	headerBlock := encodeHTTP2HeaderBlock(t,
		hpack.HeaderField{Name: ":status", Value: "418"},
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
		hpack.HeaderField{Name: "x-response-id", Value: "response-456"},
	)
	payload := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      3,
			BlockFragment: headerBlock,
			EndHeaders:    true,
		}))
		require.NoError(t, framer.WriteDataPadded(3, false, []byte("response "), make([]byte, 7)))
		require.NoError(t, framer.WriteData(3, true, []byte("body")))
	})
	buffer := largeBufferFromChunks(payload, 8, 11, len(payload)-2)
	req := &http.Request{Method: http.MethodPost}
	span := &request.Span{Status: http.StatusAccepted}

	resp, ok := parseHTTP2Response(buffer, req, span)
	require.True(t, ok)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	assert.Equal(t, "HTTP/2.0", resp.Proto)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Zero(t, resp.ProtoMinor)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "response-456", resp.Header.Get("X-Response-Id"))
	assert.Empty(t, resp.Header.Get(":status"))
	assert.Equal(t, int64(len("response body")), resp.ContentLength)
	assert.Same(t, req, resp.Request)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, []byte("response body"), body)
}

func TestParseHTTP2ResponseRejectsPayloadWithoutBody(t *testing.T) {
	resp, ok := parseHTTP2Response(largebuf.NewLargeBuffer(), &http.Request{}, &request.Span{})

	assert.False(t, ok)
	assert.Nil(t, resp)
}

func TestSniffContentEncoding(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{name: "gzip", body: []byte{0x1f, 0x8b}, want: "gzip"},
		{name: "zstd", body: []byte{0x28, 0xb5, 0x2f, 0xfd}, want: "zstd"},
		{name: "empty"},
		{name: "short gzip prefix", body: []byte{0x1f}},
		{name: "short zstd prefix", body: []byte{0x28, 0xb5, 0x2f}},
		{name: "plain body", body: []byte(`{"message":"ok"}`)},
		{name: "near gzip magic", body: []byte{0x1f, 0x8a}},
		{name: "near zstd magic", body: []byte{0x28, 0xb5, 0x2f, 0xfc}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sniffContentEncoding(tt.body))
		})
	}
}

func TestParseHTTP2ResponseContentEncoding(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		declared string
		want     string
	}{
		{name: "infers gzip", body: []byte{0x1f, 0x8b, 0x01}, want: "gzip"},
		{name: "infers zstd", body: []byte{0x28, 0xb5, 0x2f, 0xfd, 0x01}, want: "zstd"},
		{name: "leaves plain body unset", body: []byte("plain text")},
		{name: "preserves declared encoding", body: []byte{0x1f, 0x8b, 0x01}, declared: "br", want: "br"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
				if tt.declared != "" {
					headerBlock := encodeHTTP2HeaderBlock(t, hpack.HeaderField{
						Name:  "content-encoding",
						Value: tt.declared,
					})
					require.NoError(t, framer.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      1,
						BlockFragment: headerBlock,
						EndHeaders:    true,
					}))
				}
				require.NoError(t, framer.WriteData(1, true, tt.body))
			})

			resp, ok := parseHTTP2Response(
				largebuf.NewLargeBufferFrom(payload),
				&http.Request{},
				&request.Span{},
			)
			require.True(t, ok)
			assert.Equal(t, tt.want, resp.Header.Get("Content-Encoding"))
		})
	}
}

func TestExtractHTTP2DecodesContinuedHeaders(t *testing.T) {
	headerBlock := encodeHTTP2HeaderBlock(t,
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
		hpack.HeaderField{Name: "x-long-header", Value: strings.Repeat("value-", 20)},
	)
	firstSplit := len(headerBlock) / 3
	secondSplit := 2 * len(headerBlock) / 3
	payload := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: headerBlock[:firstSplit],
			EndHeaders:    false,
		}))
		require.NoError(t, framer.WriteContinuation(1, false, headerBlock[firstSplit:secondSplit]))
		require.NoError(t, framer.WriteContinuation(1, true, headerBlock[secondSplit:]))
		require.NoError(t, framer.WriteData(1, true, []byte("body")))
	})

	body, header, ok := extractHTTP2(largebuf.NewLargeBufferFrom(payload))

	require.True(t, ok)
	assert.Equal(t, []byte("body"), body)
	assert.Equal(t, "application/json", header.Get("Content-Type"))
	assert.Equal(t, strings.Repeat("value-", 20), header.Get("X-Long-Header"))
}

func TestExtractHTTP2ReturnsCapturedBodyAtEOF(t *testing.T) {
	payload := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteData(1, false, []byte("partial body")))
	})

	body, _, ok := extractHTTP2(largebuf.NewLargeBufferFrom(payload))

	require.True(t, ok)
	assert.Equal(t, []byte("partial body"), body)
}

func TestExtractHTTP2StopsAtEndStream(t *testing.T) {
	payload := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteData(1, true, []byte("complete body")))
		require.NoError(t, framer.WriteData(3, true, []byte("another stream")))
	})

	body, _, ok := extractHTTP2(largebuf.NewLargeBufferFrom(payload))

	require.True(t, ok)
	assert.Equal(t, []byte("complete body"), body)
}

func TestExtractHTTP2IgnoresNonPayloadFrames(t *testing.T) {
	payload := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteSettings(http2.Setting{
			ID:  http2.SettingMaxConcurrentStreams,
			Val: 100,
		}))
		require.NoError(t, framer.WritePing(false, [8]byte{1, 2, 3, 4}))
		require.NoError(t, framer.WriteData(1, true, []byte("body")))
	})

	body, _, ok := extractHTTP2(largebuf.NewLargeBufferFrom(payload))

	require.True(t, ok)
	assert.Equal(t, []byte("body"), body)
}

func TestExtractHTTP2FrameSizeLimit(t *testing.T) {
	t.Run("accepts frame at limit", func(t *testing.T) {
		wantBody := bytes.Repeat([]byte{'x'}, maxHTTP2ReadFrameSize)
		payload := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
			require.NoError(t, framer.WriteData(1, true, wantBody))
		})

		body, _, ok := extractHTTP2(largebuf.NewLargeBufferFrom(payload))

		require.True(t, ok)
		assert.True(t, bytes.Equal(wantBody, body))
	})

	t.Run("rejects frame above limit", func(t *testing.T) {
		payload := []byte{
			0x10, 0x00, 0x01,
			byte(http2.FrameData), byte(http2.FlagDataEndStream),
			0x00, 0x00, 0x00, 0x01,
		}

		body, header, ok := extractHTTP2(largebuf.NewLargeBufferFrom(payload))

		assert.False(t, ok)
		assert.Empty(t, body)
		assert.Empty(t, header)
	})
}

func TestExtractHTTP2IgnoresInvalidHPACKHeaders(t *testing.T) {
	payload := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: []byte{0x3f, 0xe2, 0x1f},
			EndHeaders:    true,
		}))
		require.NoError(t, framer.WriteData(1, true, []byte("body")))
	})

	body, header, ok := extractHTTP2(largebuf.NewLargeBufferFrom(payload))

	require.True(t, ok)
	assert.Equal(t, []byte("body"), body)
	assert.Empty(t, header)
}

func TestExtractHTTP2HandlesMissingContinuation(t *testing.T) {
	headerBlock := encodeHTTP2HeaderBlock(t,
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
	)
	payload := makeHTTP2Payload(t, false, func(framer *http2.Framer) {
		require.NoError(t, framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: headerBlock,
			EndHeaders:    false,
		}))
	})

	body, header, ok := extractHTTP2(largebuf.NewLargeBufferFrom(payload))

	assert.False(t, ok)
	assert.Empty(t, body)
	assert.Equal(t, "application/json", header.Get("Content-Type"))
}

func TestExtractHTTP2_CapturedResponseBuffer(t *testing.T) {
	chunk0 := []uint8{0, 0, 45, 1, 4, 0, 0, 0, 29, 136, 223, 222, 221, 220, 219, 218, 217, 216, 215, 214, 213, 212, 211, 210, 209, 208, 207, 206, 205, 204, 97, 150, 223, 105, 126, 148, 16, 84, 203, 109, 10, 8, 2, 113, 65, 6, 227, 45, 92, 11, 234, 98, 209, 191}
	chunk1 := []uint8{0, 2, 191, 0, 1, 0, 0, 0, 29, 31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 116, 84, 203, 110, 235, 54, 16, 221, 231, 43, 88, 174, 227, 128, 114, 34, 75, 246, 174, 127, 208, 69, 55, 69, 112, 33, 140, 200, 145, 205, 154, 34, 85, 114, 24, 92, 163, 240, 191, 23, 36, 45, 217, 234, 117, 118, 210, 156, 121, 159, 57, 252, 247, 133, 49, 174, 21, 63, 48, 238, 49, 76, 157, 216, 239, 218, 6, 182, 109, 187, 123, 111, 112, 219, 163, 16, 187, 253, 190, 5, 213, 192, 32, 234, 143, 182, 130, 109, 223, 139, 253, 123, 59, 52, 141, 130, 26, 246, 170, 231, 175, 41, 133, 235, 255, 70, 73, 115, 26, 103, 3, 22, 187, 244, 8, 132, 170, 131, 132, 85, 77, 83, 237, 170, 247, 122, 183, 205, 88, 32, 160, 24, 82, 140, 116, 227, 100, 144, 80, 149, 160, 30, 228, 249, 232, 93, 180, 169, 175, 1, 76, 192, 98, 214, 198, 104, 123, 228, 7, 150, 186, 102, 140, 79, 112, 65, 159, 226, 21, 126, 161, 113, 19, 122, 254, 194, 216, 181, 20, 158, 83, 174, 75, 55, 165, 52, 122, 239, 82, 164, 141, 198, 100, 195, 224, 241, 159, 136, 86, 94, 186, 9, 45, 24, 186, 240, 3, 19, 111, 34, 99, 218, 206, 201, 58, 133, 4, 218, 132, 199, 72, 109, 3, 249, 40, 73, 59, 155, 103, 249, 203, 69, 6, 30, 25, 48, 233, 148, 182, 71, 6, 33, 232, 64, 96, 137, 209, 9, 136, 17, 152, 115, 96, 70, 159, 147, 203, 164, 61, 16, 190, 149, 177, 71, 248, 217, 185, 72, 83, 164, 142, 220, 25, 237, 170, 76, 2, 201, 57, 211, 73, 48, 235, 6, 70, 167, 208, 164, 202, 199, 137, 54, 245, 102, 212, 86, 111, 182, 98, 91, 111, 68, 187, 17, 205, 141, 158, 156, 150, 31, 216, 103, 222, 92, 217, 223, 157, 249, 240, 61, 239, 253, 190, 173, 10, 239, 91, 20, 66, 41, 172, 133, 232, 133, 170, 11, 85, 57, 9, 93, 38, 44, 204, 67, 112, 54, 49, 180, 64, 33, 142, 35, 248, 180, 204, 207, 31, 217, 118, 125, 125, 214, 192, 24, 142, 223, 118, 208, 86, 66, 202, 54, 119, 208, 126, 96, 133, 80, 67, 173, 80, 170, 166, 254, 181, 131, 17, 67, 128, 35, 62, 212, 255, 230, 196, 50, 40, 157, 37, 180, 247, 173, 60, 54, 182, 74, 59, 147, 130, 63, 105, 137, 206, 14, 96, 173, 35, 152, 169, 255, 252, 177, 2, 141, 59, 78, 222, 245, 79, 144, 156, 232, 192, 248, 239, 222, 251, 223, 216, 159, 142, 201, 19, 202, 51, 211, 3, 3, 203, 138, 146, 88, 143, 233, 39, 29, 23, 88, 137, 204, 13, 233, 160, 12, 132, 192, 180, 101, 127, 92, 232, 228, 236, 43, 139, 1, 153, 14, 179, 211, 27, 95, 138, 92, 111, 95, 75, 93, 238, 157, 201, 179, 44, 215, 88, 156, 147, 99, 118, 226, 19, 120, 48, 6, 205, 250, 202, 200, 199, 34, 190, 201, 99, 64, 43, 241, 137, 62, 38, 143, 95, 218, 197, 208, 205, 210, 239, 50, 171, 203, 129, 222, 239, 98, 81, 46, 14, 131, 243, 84, 40, 83, 58, 142, 183, 181, 62, 220, 75, 138, 94, 196, 28, 208, 127, 105, 137, 29, 233, 89, 239, 3, 68, 83, 200, 224, 129, 156, 199, 199, 86, 9, 199, 9, 61, 80, 204, 230, 234, 214, 101, 25, 235, 228, 180, 44, 123, 136, 228, 248, 2, 220, 73, 226, 228, 166, 110, 122, 140, 243, 209, 202, 204, 113, 174, 172, 3, 244, 102, 126, 168, 98, 190, 182, 101, 42, 109, 87, 218, 125, 223, 189, 254, 106, 127, 120, 66, 22, 17, 72, 144, 39, 84, 247, 64, 241, 40, 21, 254, 255, 39, 97, 183, 175, 158, 33, 207, 18, 47, 155, 191, 71, 127, 124, 180, 171, 236, 228, 8, 204, 29, 110, 182, 205, 178, 245, 24, 112, 245, 70, 142, 72, 160, 128, 32, 85, 184, 190, 92, 255, 11, 0, 0, 255, 255, 24, 144, 55, 93, 59, 6, 0, 0}

	buffer := largebuf.NewLargeBuffer()
	buffer.AppendChunk(chunk0)
	buffer.AppendChunk(chunk1)

	body, header, ok := extractHTTP2(buffer)
	require.True(t, ok)

	// DATA frame length is 0x0002bf = 703 bytes, reassembled across both chunks.
	require.Len(t, body, 703)
	assert.Equal(t, "gzip", sniffContentEncoding(body), "body should be recognized as gzip")

	// The one literally-encoded header survives; dynamic-table references are dropped.
	assert.Equal(t, "Tue, 21 Jul 2026 21:34:19 GMT", header.Get("Date"))
	assert.Empty(t, header.Get("Content-Type"), "content-type was a dynamic-table reference, not recoverable")

	// The recovered body is a valid gzip stream decoding to the JSON response.
	gr, err := gzip.NewReader(bytes.NewReader(body))
	require.NoError(t, err)
	decoded, err := io.ReadAll(gr)
	require.NoError(t, err)
	assert.Contains(t, string(decoded), `"object": "response"`)
}

func FuzzExtractHTTP2(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte(http2.ClientPreface))
	f.Add([]byte{0, 0, 4, byte(http2.FrameData), byte(http2.FlagDataEndStream), 0, 0, 0, 1, 'b', 'o', 'd', 'y'})
	f.Add([]byte{0x10, 0x00, 0x01, byte(http2.FrameData), byte(http2.FlagDataEndStream), 0, 0, 0, 1})

	f.Fuzz(func(_ *testing.T, payload []byte) {
		extractHTTP2(largebuf.NewLargeBufferFrom(payload))
	})
}
