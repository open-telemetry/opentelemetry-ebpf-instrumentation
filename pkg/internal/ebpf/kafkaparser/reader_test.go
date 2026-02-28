// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import "fmt"

// bytesReader is a test helper that wraps a []byte to implement the byteReader interface.
// It is used in tests to call parser functions without depending on LargeBuffer.
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) ReadN(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("ReadN: requested %d bytes but only %d remaining", n, len(r.data)-r.pos)
	}
	s := r.data[r.pos : r.pos+n]
	r.pos += n
	return s, nil
}

func (r *bytesReader) Peek(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("Peek: requested %d bytes but only %d remaining", n, len(r.data)-r.pos)
	}
	return r.data[r.pos : r.pos+n], nil
}

func (r *bytesReader) Skip(n int) error {
	if r.pos+n > len(r.data) {
		return fmt.Errorf("Skip: requested %d bytes but only %d remaining", n, len(r.data)-r.pos)
	}
	r.pos += n
	return nil
}

func (r *bytesReader) Remaining() int {
	return len(r.data) - r.pos
}

// Pos returns the current read position (bytes consumed so far).
func (r *bytesReader) Pos() int {
	return r.pos
}
