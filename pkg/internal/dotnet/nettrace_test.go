// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

func TestReadNetTraceCompressedEventHeader(t *testing.T) {
	wire := []byte{0xff, 7, 11, 43, 2, 42, 9}
	wire = binary.AppendUvarint(wire, 123456)
	activity := [16]byte{1}
	related := [16]byte{2}
	wire = append(wire, activity[:]...)
	wire = append(wire, related[:]...)
	wire = append(wire, 3, 'a', 'b', 'c')
	reader := bytes.NewReader(wire)
	header, err := readNetTraceCompressedEventHeader(reader, netTraceEventHeader{})
	require.NoError(t, err)
	require.Equal(t, netTraceEventHeader{
		MetadataID: 7, SequenceNumber: 12, ThreadID: 42, CaptureThreadID: 43,
		CaptureProcessor: 2, StackID: 9, Timestamp: 123456,
		ActivityID: activity, RelatedActivityID: related, PayloadSize: 3, Sorted: true,
	}, header)
	require.Equal(t, 3, reader.Len())

	t.Run("inherit fields and increment sequence", func(t *testing.T) {
		got, err := readNetTraceCompressedEventHeader(bytes.NewReader([]byte{0, 5, 'd', 'e', 'f'}), header)
		require.NoError(t, err)
		want := header
		want.SequenceNumber++
		want.Timestamp += 5
		want.Sorted = false
		require.Equal(t, want, got)
	})
	t.Run("metadata events preserve sequence", func(t *testing.T) {
		previous := header
		previous.MetadataID = 0
		got, err := readNetTraceCompressedEventHeader(bytes.NewReader([]byte{0x40, 0, 'a', 'b', 'c'}), previous)
		require.NoError(t, err)
		require.Equal(t, previous, got)
	})
	t.Run("truncation leaves previous header unchanged", func(t *testing.T) {
		for length := range len(wire) {
			previous := header
			got, err := readNetTraceCompressedEventHeader(bytes.NewReader(wire[:length]), previous)
			require.Error(t, err, "truncated at byte %d", length)
			require.Zero(t, got)
			require.Equal(t, header, previous)
		}
	})
	t.Run("uint32 overflow", func(t *testing.T) {
		bad := binary.AppendUvarint([]byte{1}, 1<<32)
		_, err := readNetTraceCompressedEventHeader(bytes.NewReader(bad), netTraceEventHeader{})
		require.ErrorContains(t, err, "metadata ID exceeds uint32")
	})
	t.Run("uint64 overflow", func(t *testing.T) {
		bad := append([]byte{0}, bytes.Repeat([]byte{0xff}, 10)...)
		_, err := readNetTraceCompressedEventHeader(bytes.NewReader(bad), netTraceEventHeader{})
		require.ErrorContains(t, err, "timestamp delta")
	})
	t.Run("inherited payload must fit", func(t *testing.T) {
		_, err := readNetTraceCompressedEventHeader(bytes.NewReader([]byte{0, 0}), header)
		require.ErrorContains(t, err, "invalid NetTrace event payload size")
	})
}

func TestReadNetTraceEventBlockHeader(t *testing.T) {
	for _, flags := range []uint16{0, 1} {
		for _, size := range []uint16{20, 24} {
			wire := make([]byte, int(size)+1)
			binary.LittleEndian.PutUint16(wire, size)
			binary.LittleEndian.PutUint16(wire[2:], flags)
			wire[size] = 0xab
			reader := bytes.NewReader(wire)
			compressed, err := readNetTraceEventBlockHeader(reader)
			require.NoError(t, err)
			require.Equal(t, flags == 1, compressed)
			require.Equal(t, 1, reader.Len())
			event, err := reader.ReadByte()
			require.NoError(t, err)
			require.Equal(t, byte(0xab), event)
		}
	}
	t.Run("truncated header", func(t *testing.T) {
		wire := make([]byte, 20)
		binary.LittleEndian.PutUint16(wire, 20)
		for length := range len(wire) {
			_, err := readNetTraceEventBlockHeader(bytes.NewReader(wire[:length]))
			require.Error(t, err, "truncated at byte %d", length)
		}
	})
	t.Run("invalid size", func(t *testing.T) {
		for _, size := range []uint16{0, 4, 19} {
			wire := make([]byte, 20)
			binary.LittleEndian.PutUint16(wire, size)
			_, err := readNetTraceEventBlockHeader(bytes.NewReader(wire))
			require.ErrorContains(t, err, "invalid NetTrace event block header size")
		}
	})
	t.Run("unknown flags", func(t *testing.T) {
		wire := make([]byte, 20)
		binary.LittleEndian.PutUint16(wire, 20)
		binary.LittleEndian.PutUint16(wire[2:], 2)
		_, err := readNetTraceEventBlockHeader(bytes.NewReader(wire))
		require.ErrorContains(t, err, "unsupported NetTrace event block flags")
	})
}

func TestReadNetTraceBlock(t *testing.T) {
	const header = "\x05\x05\x01\x02\x00\x00\x00\x02\x00\x00\x00\x0a\x00\x00\x00EventBlock\x06"
	for start := range 4 {
		t.Run("alignment "+strconv.Itoa(start), func(t *testing.T) {
			wire := append([]byte(header), 3, 0, 0, 0)
			for (start+len(wire))%4 != 0 {
				wire = append(wire, 0)
			}
			wire = append(wire, 'a', 'b', 'c', 6, 1)
			reader := newNetTraceReader(iotest.OneByteReader(bytes.NewReader(wire)))
			reader.offset = int64(start)
			reader.block = make([]byte, 0, 8)
			storage := reader.block[:cap(reader.block)]
			got, payload, err := readNetTraceBlock(reader)
			require.NoError(t, err)
			require.Equal(t, netTraceObjectHeader{Name: "EventBlock", Version: 2, MinimumVersion: 2}, got)
			require.Equal(t, "abc", string(payload))
			require.Equal(t, &storage[0], &payload[0], "reuse existing storage")
			require.Equal(t, int64(start+len(wire)-1), reader.offset)
			got, payload, err = readNetTraceBlock(reader)
			require.NoError(t, err)
			require.True(t, got.EndOfStream)
			require.Nil(t, payload)
		})
	}
	t.Run("invalid sizes", func(t *testing.T) {
		for _, size := range []uint32{maximumNetTraceBlockSize + 1, 0xffffffff} {
			wire := binary.LittleEndian.AppendUint32([]byte(header), size)
			reader := newNetTraceReader(bytes.NewReader(wire))
			_, payload, err := readNetTraceBlock(reader)
			require.ErrorContains(t, err, "invalid NetTrace block size")
			require.Nil(t, payload)
			require.Nil(t, reader.block)
		}
	})
	t.Run("truncated block", func(t *testing.T) {
		wire := []byte(header + "\x03\x00\x00\x00\x00\x00abc\x06")
		for length := range len(wire) {
			_, payload, err := readNetTraceBlock(newNetTraceReader(bytes.NewReader(wire[:length])))
			require.Error(t, err, "truncated at byte %d", length)
			require.Nil(t, payload)
		}
	})
	t.Run("invalid closing tag", func(t *testing.T) {
		wire := []byte(header + "\x03\x00\x00\x00\x00\x00abc\xff")
		_, payload, err := readNetTraceBlock(newNetTraceReader(bytes.NewReader(wire)))
		require.ErrorContains(t, err, "invalid NetTrace block end tag")
		require.Nil(t, payload)
	})
}

func TestNewNetTraceReader(t *testing.T) {
	source := bytes.NewBufferString("Nettrace\x14\x00\x00\x00!FastSerialization.1")
	reader := newNetTraceReader(source)
	require.NoError(t, readNetTraceMagic(reader))
	require.Zero(t, source.Len(), "the buffer has read ahead into the serialization header")
	require.Equal(t, int64(8), reader.offset, "only the signature has been consumed")
	require.NoError(t, readFastSerializationHeader(reader))
	require.Equal(t, int64(32), reader.offset)
}

func TestNetTraceReaderRead(t *testing.T) {
	t.Run("fragmented reads accumulate offset", func(t *testing.T) {
		reader := netTraceReader{reader: iotest.OneByteReader(bytes.NewBufferString("Nettrace"))}
		require.NoError(t, readNetTraceMagic(&reader))
		require.Equal(t, int64(8), reader.offset)
		var buffer [4]byte
		n, err := reader.Read(buffer[:])
		require.Zero(t, n)
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, int64(8), reader.offset)
	})
	t.Run("bytes returned with EOF are counted", func(t *testing.T) {
		reader := netTraceReader{reader: iotest.DataErrReader(bytes.NewBufferString("abc"))}
		var buffer [8]byte
		n, err := reader.Read(buffer[:])
		require.Equal(t, 3, n)
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, "abc", string(buffer[:n]))
		require.Equal(t, int64(3), reader.offset)
	})
	t.Run("underlying error is preserved", func(t *testing.T) {
		reader := netTraceReader{reader: iotest.ErrReader(io.ErrClosedPipe)}
		var buffer [1]byte
		n, err := reader.Read(buffer[:])
		require.Zero(t, n)
		require.ErrorIs(t, err, io.ErrClosedPipe)
		require.Zero(t, reader.offset)
	})
}

func TestReadNetTracePreamble(t *testing.T) {
	const signatures = "Nettrace\x14\x00\x00\x00!FastSerialization.1"
	const header = "\x05\x05\x01\x04\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00Trace\x06"
	payload, err := hex.DecodeString("ea070900020008000a00070016009003fdc9c9107649000000ca9a3b00000000080000000f0000001000000040420f0006")
	require.NoError(t, err)
	wire := append([]byte(signatures+header), payload...)
	t.Run("fragmented preamble preserves data block", func(t *testing.T) {
		reader := bytes.NewBuffer(append(bytes.Clone(wire), 0x05))
		info, err := readNetTracePreamble(iotest.OneByteReader(reader))
		require.NoError(t, err)
		require.Equal(t, int32(15), info.ProcessID)
		require.Equal(t, int64(1_000_000_000), info.QPCFrequency)
		require.Equal(t, []byte{0x05}, reader.Bytes())
	})
	t.Run("every truncation fails", func(t *testing.T) {
		for length := range len(wire) {
			info, err := readNetTracePreamble(bytes.NewReader(wire[:length]))
			require.Error(t, err, "truncated at byte %d", length)
			require.Zero(t, info)
		}
	})
	t.Run("end marker cannot replace Trace object", func(t *testing.T) {
		info, err := readNetTracePreamble(bytes.NewBufferString(signatures + "\x01"))
		require.ErrorContains(t, err, "unsupported NetTrace Trace header")
		require.Zero(t, info)
	})
}

func TestReadNetTraceInfo(t *testing.T) {
	// Trace payload and closing tag captured from the .NET 8 reference workload.
	wire, err := hex.DecodeString("ea070900020008000a00070016009003fdc9c9107649000000ca9a3b00000000080000000f0000001000000040420f0006")
	require.NoError(t, err)
	header := netTraceObjectHeader{Name: "Trace", Version: 4, MinimumVersion: 4}
	t.Run("captured payload", func(t *testing.T) {
		reader := bytes.NewBuffer(append(bytes.Clone(wire), 0x05))
		info, err := readNetTraceInfo(iotest.OneByteReader(reader), header)
		require.NoError(t, err)
		require.Equal(t, [8]uint16{2026, 9, 2, 8, 10, 7, 22, 912}, info.SystemTime)
		require.Equal(t, int64(1_000_000_000), info.QPCFrequency)
		require.Positive(t, info.SyncTimeQPC)
		require.Equal(t, int32(8), info.PointerSize)
		require.Equal(t, int32(15), info.ProcessID)
		require.Equal(t, int32(16), info.ProcessorCount)
		require.Equal(t, int32(1_000_000), info.CPUSamplingRate)
		require.Equal(t, []byte{0x05}, reader.Bytes())
	})
	t.Run("unsupported header", func(t *testing.T) {
		for _, invalid := range []netTraceObjectHeader{
			{Name: "EventBlock", Version: 4},
			{Name: "Trace", Version: 3},
			{Name: "Trace", Version: 5},
			{Name: "Trace", Version: 4, MinimumVersion: 5},
			{Name: "Trace", Version: 4, MinimumVersion: -1},
			{EndOfStream: true},
		} {
			reader := bytes.NewReader(wire)
			info, err := readNetTraceInfo(reader, invalid)
			require.ErrorContains(t, err, "unsupported NetTrace Trace header")
			require.Zero(t, info)
			require.Equal(t, len(wire), reader.Len())
		}
	})
	t.Run("invalid payload", func(t *testing.T) {
		for _, tc := range []struct {
			offset int
			value  byte
			err    string
		}{
			{31, 0x80, "invalid NetTrace clock frequency"},
			{32, 3, "invalid NetTrace pointer size"},
			{48, 0, "invalid NetTrace Trace end tag"},
		} {
			bad := bytes.Clone(wire)
			bad[tc.offset] = tc.value
			info, err := readNetTraceInfo(bytes.NewReader(bad), header)
			require.ErrorContains(t, err, tc.err)
			require.Zero(t, info)
		}
	})
	t.Run("truncated payload", func(t *testing.T) {
		for length := range len(wire) {
			info, err := readNetTraceInfo(bytes.NewReader(wire[:length]), header)
			if length == 0 || length == 48 {
				require.ErrorIs(t, err, io.EOF)
			} else {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			}
			require.Zero(t, info)
		}
	})
}

func TestReadNetTraceObjectHeader(t *testing.T) {
	const header = "\x05\x05\x01\x04\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00Trace\x06"
	t.Run("fragmented reads preserve payload", func(t *testing.T) {
		reader := bytes.NewBufferString(header + "payload")
		got, err := readNetTraceObjectHeader(iotest.OneByteReader(reader))
		require.NoError(t, err)
		require.Equal(t, netTraceObjectHeader{Name: "Trace", Version: 4, MinimumVersion: 4}, got)
		require.Equal(t, "payload", reader.String())
	})

	t.Run("explicit end of stream", func(t *testing.T) {
		reader := bytes.NewBufferString("\x01remaining")
		got, err := readNetTraceObjectHeader(reader)
		require.NoError(t, err)
		require.Equal(t, netTraceObjectHeader{EndOfStream: true}, got)
		require.Equal(t, "remaining", reader.String())
	})

	t.Run("invalid tags", func(t *testing.T) {
		for _, offset := range []int{0, 1, 2, len(header) - 1} {
			t.Run(strconv.Itoa(offset), func(t *testing.T) {
				wire := []byte(header)
				wire[offset] = 0xff
				got, err := readNetTraceObjectHeader(bytes.NewReader(wire))
				require.ErrorContains(t, err, "invalid NetTrace")
				require.Zero(t, got)
			})
		}
	})

	t.Run("invalid lengths leave name unread", func(t *testing.T) {
		for _, length := range []uint32{0, 39, 0x7fffffff, 0xffffffff} {
			t.Run(strconv.FormatUint(uint64(length), 10), func(t *testing.T) {
				wire := []byte(header)
				binary.LittleEndian.PutUint32(wire[11:15], length)
				reader := bytes.NewReader(wire)
				got, err := readNetTraceObjectHeader(reader)
				require.ErrorContains(t, err, "invalid NetTrace type name length")
				require.Zero(t, got)
				require.Equal(t, len("Trace\x06"), reader.Len())
			})
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		for length := range len(header) {
			t.Run(strconv.Itoa(length), func(t *testing.T) {
				got, err := readNetTraceObjectHeader(bytes.NewBufferString(header[:length]))
				if length == 0 || length == 1 || length == 3 || length == 15 || length == 20 {
					require.ErrorIs(t, err, io.EOF)
				} else {
					require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				}
				require.Zero(t, got)
			})
		}
	})
}

func TestReadNetTraceMagic(t *testing.T) {
	t.Run("fragmented reads preserve following header", func(t *testing.T) {
		const header = "\x14\x00\x00\x00!FastSerialization.1"
		reader := bytes.NewBufferString("Nettrace" + header)
		require.NoError(t, readNetTraceMagic(iotest.OneByteReader(reader)))
		require.Equal(t, header, reader.String())
	})

	t.Run("incorrect signature", func(t *testing.T) {
		require.ErrorContains(t, readNetTraceMagic(bytes.NewBufferString("NetTrace")),
			"invalid NetTrace signature")
	})

	t.Run("truncated signature", func(t *testing.T) {
		const signature = "Nettrace"
		for length := range len(signature) {
			t.Run(strconv.Itoa(length), func(t *testing.T) {
				err := readNetTraceMagic(bytes.NewBufferString(signature[:length]))
				if length == 0 {
					require.ErrorIs(t, err, io.EOF)
				} else {
					require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				}
			})
		}
	})
}

func TestReadFastSerializationHeader(t *testing.T) {
	const header = "\x14\x00\x00\x00!FastSerialization.1"
	t.Run("fragmented reads preserve first object", func(t *testing.T) {
		reader := bytes.NewBufferString(header + "\x05")
		require.NoError(t, readFastSerializationHeader(iotest.OneByteReader(reader)))
		require.Equal(t, "\x05", reader.String())
	})

	t.Run("invalid lengths leave marker unread", func(t *testing.T) {
		for _, length := range []string{
			"\x00\x00\x00\x00",
			"\x13\x00\x00\x00",
			"\x15\x00\x00\x00",
			"\x00\x00\x00\x14",
			"\xff\xff\xff\xff",
		} {
			reader := bytes.NewBufferString(length + header[4:])
			require.ErrorContains(t, readFastSerializationHeader(reader),
				"invalid FastSerialization marker length")
			require.Equal(t, header[4:], reader.String())
		}
	})

	t.Run("incorrect marker", func(t *testing.T) {
		reader := bytes.NewBufferString("\x14\x00\x00\x00!FastSerialization.2")
		require.ErrorContains(t, readFastSerializationHeader(reader),
			"invalid FastSerialization marker:")
	})

	t.Run("truncated header", func(t *testing.T) {
		for length := range len(header) {
			t.Run(strconv.Itoa(length), func(t *testing.T) {
				err := readFastSerializationHeader(bytes.NewBufferString(header[:length]))
				if length == 0 || length == 4 {
					require.ErrorIs(t, err, io.EOF)
				} else {
					require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				}
			})
		}
	})
}
