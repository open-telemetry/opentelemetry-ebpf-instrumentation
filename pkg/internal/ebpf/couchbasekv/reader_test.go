// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package couchbasekv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketReaderOffset(t *testing.T) {
	pkt := make([]byte, 100)
	r := NewPacketReader(pkt, 10)

	assert.Equal(t, 10, r.Offset())

	r.SetOffset(50)
	assert.Equal(t, 50, r.Offset())
}

func TestPacketReaderRemaining(t *testing.T) {
	pkt := make([]byte, 100)
	r := NewPacketReader(pkt, 10)

	assert.Equal(t, 90, r.Remaining())

	r.SetOffset(90)
	assert.Equal(t, 10, r.Remaining())
}

func TestPacketReaderSkip(t *testing.T) {
	pkt := make([]byte, 100)
	r := NewPacketReader(pkt, 0)

	err := r.Skip(10)
	require.NoError(t, err)
	assert.Equal(t, 10, r.Offset())

	err = r.Skip(50)
	require.NoError(t, err)
	assert.Equal(t, 60, r.Offset())

	// Try to skip past end
	err = r.Skip(50)
	assert.Error(t, err)
}

func TestPacketReaderReadUint8(t *testing.T) {
	pkt := []byte{0x12, 0x34, 0x56}
	r := NewPacketReader(pkt, 0)

	v, err := r.ReadUint8()
	require.NoError(t, err)
	assert.Equal(t, uint8(0x12), v)
	assert.Equal(t, 1, r.Offset())

	v, err = r.ReadUint8()
	require.NoError(t, err)
	assert.Equal(t, uint8(0x34), v)

	v, err = r.ReadUint8()
	require.NoError(t, err)
	assert.Equal(t, uint8(0x56), v)

	// Try to read past end
	_, err = r.ReadUint8()
	assert.Error(t, err)
}

func TestPacketReaderReadUint16(t *testing.T) {
	pkt := []byte{0x12, 0x34, 0x56, 0x78}
	r := NewPacketReader(pkt, 0)

	v, err := r.ReadUint16()
	require.NoError(t, err)
	assert.Equal(t, uint16(0x1234), v)
	assert.Equal(t, 2, r.Offset())

	v, err = r.ReadUint16()
	require.NoError(t, err)
	assert.Equal(t, uint16(0x5678), v)

	// Try to read past end
	_, err = r.ReadUint16()
	assert.Error(t, err)
}

func TestPacketReaderReadUint32(t *testing.T) {
	pkt := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	r := NewPacketReader(pkt, 0)

	v, err := r.ReadUint32()
	require.NoError(t, err)
	assert.Equal(t, uint32(0x12345678), v)
	assert.Equal(t, 4, r.Offset())

	v, err = r.ReadUint32()
	require.NoError(t, err)
	assert.Equal(t, uint32(0x9ABCDEF0), v)

	// Try to read past end
	_, err = r.ReadUint32()
	assert.Error(t, err)
}

func TestPacketReaderReadUint64(t *testing.T) {
	pkt := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22}
	r := NewPacketReader(pkt, 0)

	v, err := r.ReadUint64()
	require.NoError(t, err)
	assert.Equal(t, uint64(0x123456789ABCDEF0), v)
	assert.Equal(t, 8, r.Offset())

	// Try to read past end
	_, err = r.ReadUint64()
	assert.Error(t, err)
}

func TestPacketReaderReadBytes(t *testing.T) {
	pkt := []byte{0x12, 0x34, 0x56, 0x78, 0x9A}
	r := NewPacketReader(pkt, 0)

	data, err := r.ReadBytes(3)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x12, 0x34, 0x56}, data)
	assert.Equal(t, 3, r.Offset())

	data, err = r.ReadBytes(2)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x78, 0x9A}, data)

	// Try to read past end
	_, err = r.ReadBytes(1)
	assert.Error(t, err)
}

func TestPacketReaderReadString(t *testing.T) {
	pkt := []byte("hello world")
	r := NewPacketReader(pkt, 0)

	s, err := r.ReadString(5)
	require.NoError(t, err)
	assert.Equal(t, "hello", s)
	assert.Equal(t, 5, r.Offset())

	// Skip space
	err = r.Skip(1)
	require.NoError(t, err)

	s, err = r.ReadString(5)
	require.NoError(t, err)
	assert.Equal(t, "world", s)

	// Try to read past end
	_, err = r.ReadString(1)
	assert.Error(t, err)
}

func TestPacketReaderPeekUint8(t *testing.T) {
	pkt := []byte{0x12, 0x34}
	r := NewPacketReader(pkt, 0)

	v, err := r.PeekUint8()
	require.NoError(t, err)
	assert.Equal(t, uint8(0x12), v)
	assert.Equal(t, 0, r.Offset()) // Offset should not change

	// Read to advance
	_, _ = r.ReadUint8()
	v, err = r.PeekUint8()
	require.NoError(t, err)
	assert.Equal(t, uint8(0x34), v)

	// Advance to end
	_, _ = r.ReadUint8()
	_, err = r.PeekUint8()
	assert.Error(t, err)
}

func TestPacketReaderReadHeader(t *testing.T) {
	// Create a valid header with key
	pkt := makeRequestHeader(OpcodeGet, 5, 0, 5, 100, 12345, 0)
	pkt = append(pkt, []byte("mykey")...)

	r := NewPacketReader(pkt, 0)

	h, err := r.ReadHeader()
	require.NoError(t, err)
	require.NotNil(t, h)

	assert.Equal(t, MagicClientRequest, h.Magic)
	assert.Equal(t, OpcodeGet, h.Opcode)
	assert.Equal(t, uint16(5), h.KeyLen)
	assert.Equal(t, HeaderLen, r.Offset())

	// Can continue reading key
	key, err := r.ReadString(int(h.KeyLen))
	require.NoError(t, err)
	assert.Equal(t, "mykey", key)
}

func TestPacketReaderReadHeaderNotEnoughData(t *testing.T) {
	pkt := make([]byte, 10) // Less than HeaderLen
	r := NewPacketReader(pkt, 0)

	_, err := r.ReadHeader()
	assert.Error(t, err)
}
