// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package bhpack

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	xhpack "golang.org/x/net/http2/hpack"
)

func TestDecoderMatchesReference(t *testing.T) {
	tests := []struct {
		name   string
		max    uint32
		blocks []string
	}{
		{
			name: "RFC 7541 C.2 representations",
			max:  4096,
			blocks: []string{
				"400a637573746f6d2d6b65790d637573746f6d2d686561646572",
				"040c2f73616d706c652f70617468",
				"100870617373776f726406736563726574",
				"82",
			},
		},
		{
			name: "RFC 7541 C.3 dynamic request sequence",
			max:  4096,
			blocks: []string{
				"828684410f7777772e6578616d706c652e636f6d",
				"828684be58086e6f2d6361636865",
				"828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
			},
		},
		{
			name: "RFC 7541 C.4 Huffman request sequence",
			max:  4096,
			blocks: []string{
				"828684418cf1e3c2e5f23a6ba0ab90f4ff",
				"828684be5886a8eb10649cbf",
				"828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
			},
		},
		{
			name: "table update and ordered literal forms",
			max:  256,
			blocks: []string{
				"3f6182400178017904022f7810036b657906736563726574",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDecoder := NewDecoder(tt.max, nil)
			wantDecoder := xhpack.NewDecoder(tt.max, nil)
			for i, encoded := range tt.blocks {
				block := decodeHex(t, encoded)
				got, gotErr := gotDecoder.DecodeFull(block)
				want, wantErr := wantDecoder.DecodeFull(block)

				require.NoError(t, gotErr, "block %d", i)
				require.NoError(t, wantErr, "reference block %d", i)
				require.Equal(t, fromReference(want), got, "block %d field order", i)
				require.LessOrEqual(t, gotDecoder.dynTab.size, gotDecoder.dynTab.maxSize)
			}
		})
	}
}

func TestDecoderDynamicTableEvictionAndMaximum(t *testing.T) {
	decoder := NewDecoder(68, nil)
	reference := xhpack.NewDecoder(68, nil)

	for _, block := range [][]byte{
		literalWithIndexing("x", "a"),
		literalWithIndexing("y", "b"),
		literalWithIndexing("z", "c"),
	} {
		got, gotErr := decoder.DecodeFull(block)
		want, wantErr := reference.DecodeFull(block)
		require.NoError(t, gotErr)
		require.NoError(t, wantErr)
		require.Equal(t, fromReference(want), got)
		require.LessOrEqual(t, decoder.dynTab.size, decoder.dynTab.maxSize)
	}

	require.Equal(t, uint32(68), decoder.dynTab.size)
	require.Equal(t, []HeaderField{{Name: "y", Value: "b"}, {Name: "z", Value: "c"}}, decoder.dynTab.table.ents)

	fields, err := decoder.DecodeFull([]byte{0xbe, 0xbf})
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "z", Value: "c"}, {Name: "y", Value: "b"}}, fields)

	fields, err = decoder.DecodeFull([]byte{0x20, 0x82})
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: ":method", Value: "GET"}}, fields)
	require.Zero(t, decoder.dynTab.size)
	require.Empty(t, decoder.dynTab.table.ents)
}

func TestDecoderAllowsTwoLeadingTableSizeUpdates(t *testing.T) {
	block := []byte{0x20, 0x3f, 0x61, 0x82}
	decoder := NewDecoder(256, nil)
	reference := xhpack.NewDecoder(256, nil)

	got, gotErr := decoder.DecodeFull(block)
	want, wantErr := reference.DecodeFull(block)
	require.NoError(t, gotErr)
	require.NoError(t, wantErr)
	require.Equal(t, fromReference(want), got)
	require.Equal(t, []HeaderField{{Name: ":method", Value: "GET"}}, got)

	_, err := NewDecoder(256, nil).DecodeFull([]byte{0x20, 0x20, 0x20})
	require.Error(t, err)
}

func TestHuffmanMatchesReference(t *testing.T) {
	allOctets := make([]byte, 256)
	for i := range allOctets {
		allOctets[i] = byte(i)
	}
	for _, value := range []string{"", "www.example.com", string(allOctets)} {
		gotEncoding := AppendHuffmanString(nil, value)
		wantEncoding := xhpack.AppendHuffmanString(nil, value)
		require.Equal(t, wantEncoding, gotEncoding)

		got, gotErr := HuffmanDecodeToString(gotEncoding)
		want, wantErr := xhpack.HuffmanDecodeToString(wantEncoding)
		require.NoError(t, gotErr)
		require.NoError(t, wantErr)
		require.Equal(t, want, got)
	}

	for _, encoded := range [][]byte{
		{0xff},
		{0x1f, 0xff},
		{0xff, 0xff, 0xff, 0xff, 0xfc},
		{0x00},
		[]byte("00\x91\xff\xff\xff\xff\xc8"),
	} {
		got, gotErr := HuffmanDecodeToString(encoded)
		want, wantErr := xhpack.HuffmanDecodeToString(encoded)
		require.Equal(t, want, got)
		require.Equal(t, errorText(wantErr), errorText(gotErr))
	}
}

func TestDecoderRejectsMalformedInputDeterministically(t *testing.T) {
	varintOverflow := append([]byte{0xff}, make([]byte, 10)...)
	for i := 1; i < len(varintOverflow); i++ {
		varintOverflow[i] = 0x80
	}

	tests := []struct {
		name  string
		block []byte
	}{
		{name: "truncated indexed integer", block: []byte{0xff}},
		{name: "indexed integer overflow", block: varintOverflow},
		{name: "truncated literal name", block: []byte{0x40, 0x03, 'a'}},
		{name: "truncated literal value", block: []byte{0x40, 0x01, 'a', 0x02, 'b'}},
		{name: "invalid Huffman padding", block: []byte{0x00, 0x81, 0x00, 0x00}},
		{name: "table update above allowed maximum", block: []byte{0x3f, 0x61}},
		{name: "table update after a field", block: append(literalWithIndexing("x", "y"), 0x20)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var previous string
			for run := range 2 {
				decoder := NewDecoder(64, nil)
				fields, err := decoder.DecodeFull(tt.block)
				require.Error(t, err)
				require.Empty(t, fields)
				require.LessOrEqual(t, decoder.dynTab.size, decoder.dynTab.maxSize)
				if run > 0 {
					require.Equal(t, previous, err.Error())
				}
				previous = err.Error()

				_ = decoder.Close()
				fields, err = decoder.DecodeFull([]byte{0x82})
				require.NoError(t, err)
				require.Equal(t, []HeaderField{{Name: ":method", Value: "GET"}}, fields)
			}

			reference := xhpack.NewDecoder(64, nil)
			_, err := reference.DecodeFull(tt.block)
			require.Error(t, err)
		})
	}
}

func TestDecoderContainsInvalidIndexes(t *testing.T) {
	// OBI can start observing mid-connection without the peer's dynamic table.
	// It emits a sentinel for those indexes while a strict decoder rejects them.
	tests := []struct {
		name  string
		block []byte
	}{
		{name: "zero indexed field", block: []byte{0x80}},
		{name: "missing dynamic indexed field", block: []byte{0xbe}},
		{name: "missing dynamic literal name", block: []byte{0x0f, 0x2f, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := NewDecoder(64, nil)
			fields, err := decoder.DecodeFull(tt.block)
			require.NoError(t, err)
			require.Equal(t, []HeaderField{{Name: "<BAD INDEX>"}}, fields)
			require.LessOrEqual(t, decoder.dynTab.size, decoder.dynTab.maxSize)

			reference := xhpack.NewDecoder(64, nil)
			_, err = reference.DecodeFull(tt.block)
			require.Error(t, err)
		})
	}
}

func TestDecoderContainsLargeUnresolvedIndex(t *testing.T) {
	encoded := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
	index, remain, err := readVarInt(7, encoded)
	require.NoError(t, err)
	require.Equal(t, uint64(1<<63)+126, index)
	require.Empty(t, remain)

	decoder := NewDecoder(64, nil)
	fields, err := decoder.DecodeFull(encoded)
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "<BAD INDEX>"}}, fields)
	require.True(t, decoder.failedToIndex)
	require.Empty(t, decoder.dynTab.table.ents)
}

func TestDecoderDoesNotIndexUnresolvedLiteralName(t *testing.T) {
	decoder := NewDecoder(64, nil)

	fields, err := decoder.DecodeFull([]byte{0x7e, 0x01, 'v'})
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "<BAD INDEX>", Value: "v"}}, fields)
	require.True(t, decoder.failedToIndex)
	require.Empty(t, decoder.dynTab.table.ents)

	fields, err = decoder.DecodeFull([]byte{0xbe})
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "<BAD INDEX>"}}, fields)
}

func TestDecoderRejectsLateTableSizeUpdateWithEmptyTable(t *testing.T) {
	decoder := NewDecoder(64, nil)

	fields, err := decoder.DecodeFull([]byte{0x82, 0x20})
	require.Error(t, err)
	require.Empty(t, fields)
	require.Empty(t, decoder.dynTab.table.ents)
}

func TestDecoderTruncationDoesNotPoisonLaterBlocks(t *testing.T) {
	decoder := NewDecoder(256, func(HeaderField) {})

	_, err := decoder.DecodeFull([]byte("\x40\x04seed\x01v"))
	require.NoError(t, err)

	_, err = decoder.Write([]byte("\x20\x3f\x61\x40\x07partial\x01v\x40\x01x"))
	require.NoError(t, err)
	require.Error(t, decoder.Close())

	fields, err := decoder.DecodeFull([]byte("\x20\x40\x01x\x01y"))
	require.NoError(t, err)
	require.Equal(t, []HeaderField{{Name: "x", Value: "y"}}, fields)
}

func FuzzHPACKDecoder(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{0x82},
		literalWithIndexing("x", "y"),
		decodeHex(f, "828684418cf1e3c2e5f23a6ba0ab90f4ff"),
		{0x80},
		{0xff},
		{0x00, 0x81, 0x00, 0x00},
		{0x82, 0x20},
		{0x20, 0x3f, 0x61, 0x82},
		{0x20, 0x20, 0x20},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		const (
			maxInput  = 512
			maxTable  = 256
			maxString = 256
		)
		if len(input) > maxInput {
			input = input[:maxInput]
		}

		decode := func() ([]HeaderField, string, uint32) {
			decoder := NewDecoder(maxTable, nil)
			decoder.SetMaxStringLength(maxString)
			fields, err := decoder.DecodeFull(input)
			if err != nil {
				_ = decoder.Close()
			}
			require.LessOrEqual(t, decoder.dynTab.size, decoder.dynTab.maxSize)
			return fields, errorText(err), decoder.dynTab.size
		}

		fields, decodeErr, tableSize := decode()
		repeatFields, repeatErr, repeatTableSize := decode()
		require.Equal(t, fields, repeatFields)
		require.Equal(t, decodeErr, repeatErr)
		require.Equal(t, tableSize, repeatTableSize)

		reference := xhpack.NewDecoder(maxTable, nil)
		reference.SetMaxStringLength(maxString)
		want, referenceErr := reference.DecodeFull(input)
		if referenceErr == nil {
			if decodeErr != "" {
				require.Equal(t, lateTableSizeUpdateError, decodeErr)
				emitted, leadingUpdates, incrementalErr := decodeIncrementally(input, maxTable, maxString)
				require.Equal(t, decodeErr, errorText(incrementalErr))
				lateAfterField := len(emitted) > 0
				thirdLeadingUpdate := len(emitted) == 0 && leadingUpdates == 2
				require.True(t, lateAfterField || thirdLeadingUpdate)
				return
			}
			require.Equal(t, fromReference(want), fields)
			return
		}
		if decodeErr == "" {
			require.True(t, isReferenceInvalidIndex(referenceErr), "unexpected reference rejection: %v", referenceErr)
		}
	})
}

const lateTableSizeUpdateError = "decoding error: dynamic table size update MUST occur at the beginning of a header block"

func isReferenceInvalidIndex(err error) bool {
	var decodingError xhpack.DecodingError
	if !errors.As(err, &decodingError) {
		return false
	}
	var invalidIndex xhpack.InvalidIndexError
	return errors.As(decodingError.Err, &invalidIndex)
}

func decodeIncrementally(input []byte, maxTable uint32, maxString int) ([]HeaderField, uint8, error) {
	var fields []HeaderField
	decoder := NewDecoder(maxTable, func(field HeaderField) {
		fields = append(fields, field)
	})
	decoder.SetMaxStringLength(maxString)
	_, err := decoder.Write(input)
	return fields, decoder.tableSizeUpdates, err
}

type testHelper interface {
	Helper()
	Fatalf(string, ...any)
}

func decodeHex(t testHelper, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.ReplaceAll(encoded, " ", ""))
	if err != nil {
		t.Fatalf("decode HPACK fixture: %v", err)
	}
	return decoded
}

func fromReference(fields []xhpack.HeaderField) []HeaderField {
	if len(fields) == 0 {
		return nil
	}
	converted := make([]HeaderField, len(fields))
	for i, field := range fields {
		converted[i] = HeaderField{
			Name:      field.Name,
			Value:     field.Value,
			Sensitive: field.Sensitive,
		}
	}
	return converted
}

func literalWithIndexing(name, value string) []byte {
	encoded := []byte{0x40, byte(len(name))}
	encoded = append(encoded, name...)
	encoded = append(encoded, byte(len(value)))
	return append(encoded, value...)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
