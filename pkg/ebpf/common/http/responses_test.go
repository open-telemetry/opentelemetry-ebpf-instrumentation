// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const testPayload = `{"hello":"world"}`

// helpers to produce compressed bytes

func gzipEncode(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func zstdEncode(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func deflateEncode(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func brotliEncode(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func makeResponse(t *testing.T, body []byte, encoding string) *http.Response {
	t.Helper()
	resp := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader(body)),
	}
	if encoding != "" {
		resp.Header.Set("Content-Encoding", encoding)
	}
	return resp
}

func TestDecompressBody(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		encode   func(*testing.T, []byte) []byte
	}{
		{"gzip", "gzip", gzipEncode},
		{"zstd", "zstd", zstdEncode},
		{"deflate", "deflate", deflateEncode},
		{"brotli", "br", brotliEncode},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compressed := tc.encode(t, []byte(testPayload))
			got, err := decompressBody(tc.encoding, compressed)
			if err != nil {
				t.Fatalf("decompressBody(%q): unexpected error: %v", tc.encoding, err)
			}
			if string(got) != testPayload {
				t.Errorf("decompressBody(%q): got %q, want %q", tc.encoding, got, testPayload)
			}
		})
	}

	t.Run("unknown encoding passthrough", func(t *testing.T) {
		got, err := decompressBody("identity", []byte(testPayload))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != testPayload {
			t.Errorf("got %q, want %q", got, testPayload)
		}
	})

	t.Run("gzip corrupted data returns error", func(t *testing.T) {
		_, err := decompressBody("gzip", []byte("notgzip"))
		if err == nil {
			t.Fatal("expected error for corrupted gzip data, got nil")
		}
	})

	t.Run("zstd corrupted data returns error", func(t *testing.T) {
		_, err := decompressBody("zstd", []byte("notzstd"))
		if err == nil {
			t.Fatal("expected error for corrupted zstd data, got nil")
		}
	})

	t.Run("brotli corrupted data returns error", func(t *testing.T) {
		_, err := decompressBody("br", []byte("notbrotli"))
		if err == nil {
			t.Fatal("expected error for corrupted brotli data, got nil")
		}
	})

	t.Run("gzip decompression over limit returns error", func(t *testing.T) {
		payload := bytes.Repeat([]byte("a"), maxDecompressedResponseBodyBytes+1)
		_, err := decompressBody("gzip", gzipEncode(t, payload))
		if !errors.Is(err, errResponseBodyTooLarge) {
			t.Fatalf("expected errResponseBodyTooLarge, got %v", err)
		}
	})
}

func TestGetResponseBody(t *testing.T) {
	t.Run("no encoding returns plain body", func(t *testing.T) {
		resp := makeResponse(t, []byte(testPayload), "")
		got, err := getResponseBody(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != testPayload {
			t.Errorf("got %q, want %q", got, testPayload)
		}
	})

	t.Run("gzip encoding decompressed", func(t *testing.T) {
		resp := makeResponse(t, gzipEncode(t, []byte(testPayload)), "gzip")
		got, err := getResponseBody(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != testPayload {
			t.Errorf("got %q, want %q", got, testPayload)
		}
	})

	t.Run("zstd encoding decompressed", func(t *testing.T) {
		resp := makeResponse(t, zstdEncode(t, []byte(testPayload)), "zstd")
		got, err := getResponseBody(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != testPayload {
			t.Errorf("got %q, want %q", got, testPayload)
		}
	})

	t.Run("deflate encoding decompressed", func(t *testing.T) {
		resp := makeResponse(t, deflateEncode(t, []byte(testPayload)), "deflate")
		got, err := getResponseBody(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != testPayload {
			t.Errorf("got %q, want %q", got, testPayload)
		}
	})

	t.Run("brotli encoding decompressed", func(t *testing.T) {
		resp := makeResponse(t, brotliEncode(t, []byte(testPayload)), "br")
		got, err := getResponseBody(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != testPayload {
			t.Errorf("got %q, want %q", got, testPayload)
		}
	})

	t.Run("empty body with encoding header returns empty", func(t *testing.T) {
		resp := makeResponse(t, []byte{}, "gzip")
		got, err := getResponseBody(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty body, got %q", got)
		}
	})

	t.Run("body is restored and readable after call", func(t *testing.T) {
		resp := makeResponse(t, []byte(testPayload), "")
		_, err := getResponseBody(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// resp.Body should have been replaced with a fresh reader
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("re-reading body: %v", err)
		}
		if string(b) != testPayload {
			t.Errorf("restored body: got %q, want %q", b, testPayload)
		}
	})

	t.Run("corrupted gzip body returns error", func(t *testing.T) {
		resp := makeResponse(t, []byte("notgzip"), "gzip")
		_, err := getResponseBody(resp)
		if err == nil {
			t.Fatal("expected error for corrupted gzip body, got nil")
		}
		if !strings.Contains(err.Error(), "decompress error") {
			t.Errorf("error message should mention decompress error, got: %v", err)
		}
	})

	t.Run("compressed body over limit returns error and body is restored", func(t *testing.T) {
		payload := bytes.Repeat([]byte("a"), maxDecompressedResponseBodyBytes+1)
		compressed := gzipEncode(t, payload)
		resp := makeResponse(t, compressed, "gzip")

		_, err := getResponseBody(resp)
		if !errors.Is(err, errResponseBodyTooLarge) {
			t.Fatalf("expected errResponseBodyTooLarge, got %v", err)
		}

		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("re-reading body after limit error: %v", readErr)
		}
		if !bytes.Equal(body, compressed) {
			t.Fatal("response body was not restored after decompression limit error")
		}
	})
}
