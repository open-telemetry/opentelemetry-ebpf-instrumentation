// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package bhpack

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

func decodeAll(t *testing.T, d *Decoder, block []byte) []HeaderField {
	t.Helper()
	var fields []HeaderField
	d.SetEmitFunc(func(hf HeaderField) { fields = append(fields, hf) })
	_, err := d.Write(block)
	require.NoError(t, err)
	return fields
}

// One failed index lookup must stop the decoder from trusting any later
// dynamic-table resolution: a desynced table can name the wrong field.
func TestDesyncFreezesDynamicTableLookups(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)

	require.NoError(t, enc.WriteField(hpack.HeaderField{Name: "x-a", Value: "1"}))
	require.NoError(t, enc.WriteField(hpack.HeaderField{Name: "x-b", Value: "2"}))
	insertions := append([]byte{}, buf.Bytes()...)

	buf.Reset()
	require.NoError(t, enc.WriteField(hpack.HeaderField{Name: "x-a", Value: "1"}))
	require.NoError(t, enc.WriteField(hpack.HeaderField{Name: "x-b", Value: "2"}))
	indexedRefs := append([]byte{}, buf.Bytes()...)

	d := NewDecoder(4096, nil)

	fields := decodeAll(t, d, insertions)
	require.Equal(t, []HeaderField{
		{Name: "x-a", Value: "1"},
		{Name: "x-b", Value: "2"},
	}, fields)

	// in-sync dynamic references resolve
	fields = decodeAll(t, d, indexedRefs)
	require.Equal(t, "x-a", fields[0].Name)
	require.Equal(t, "x-b", fields[1].Name)

	// indexed reference far past the table: the desync signal
	fields = decodeAll(t, d, []byte{0x80 | 100})
	require.Equal(t, "<BAD INDEX>", fields[0].Name)

	// the same dynamic references that resolved before must now be distrusted
	fields = decodeAll(t, d, indexedRefs)
	assert.Equal(t, "<BAD INDEX>", fields[0].Name)
	assert.Equal(t, "<BAD INDEX>", fields[1].Name)

	// static table entries stay valid (index 2 = ":method: GET")
	fields = decodeAll(t, d, []byte{0x80 | 2})
	assert.Equal(t, ":method", fields[0].Name)
	assert.Equal(t, "GET", fields[0].Value)
}

// A miss on a literal field's name index is the same desync signal: it must set
// the freeze and keep the poisoned entry out of the dynamic table.
func TestLiteralNameIndexMissFreezesTable(t *testing.T) {
	d := NewDecoder(4096, nil)

	// literal with incremental indexing, name index 100 (6-bit prefix varint),
	// value "v" — the name index cannot resolve
	block := []byte{0x40 | 0x3f, 100 - 0x3f, 0x01, 'v'}
	fields := decodeAll(t, d, block)
	require.Equal(t, "<BAD INDEX>", fields[0].Name)
	require.Equal(t, "v", fields[0].Value)

	// insertions are frozen from here on, so this literal must not land in the
	// table...
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	require.NoError(t, enc.WriteField(hpack.HeaderField{Name: "x-a", Value: "1"}))
	fields = decodeAll(t, d, buf.Bytes())
	require.Equal(t, "x-a", fields[0].Name)

	// ...and the dynamic reference to it must be distrusted, not resolved
	fields = decodeAll(t, d, []byte{0x80 | 62})
	assert.Equal(t, "<BAD INDEX>", fields[0].Name)
}
