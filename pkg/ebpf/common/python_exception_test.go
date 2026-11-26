// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/ebpf-profiler/remotememory"

	"go.opentelemetry.io/obi/pkg/exceptions"
)

func TestPythonLine(t *testing.T) {
	for _, tc := range []struct {
		name             string
		table            []byte
		first, pos, want uint32
		invalid          bool
	}{
		{"short", []byte{128, 0}, 10, 0, 10, false},
		{"one line", []byte{216, 1, 2}, 10, 0, 11, false},
		{"signed", []byte{232, 3}, 10, 0, 9, false},
		{"long", []byte{240, 4, 0, 1, 1}, 10, 0, 12, false},
		{"second entry", []byte{128, 0, 216, 1, 2}, 10, 1, 11, false},
		{"no source line preserves subsequent base", []byte{248, 232, 2}, 10, 1, 11, false},
		{"no source line", []byte{248}, 10, 0, 0, true},
		{"truncated varint", []byte{232, 64}, 10, 0, 0, true},
		{"overflowing varint", []byte{232, 127, 127, 127, 127, 127, 127}, 10, 0, 0, true},
		{"truncated columns", []byte{216, 1}, 10, 0, 0, true},
		{"past the table", []byte{128, 0}, 10, 1, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := pythonLine(tc.table, tc.first, tc.pos)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, line)
		})
	}
}

func TestPythonLegacyLine(t *testing.T) {
	for _, tc := range []struct {
		name             string
		minor            uint8
		table            []byte
		first, pos, want uint32
		invalid          bool
	}{
		{"39 signed delta", 9, []byte{2, 3, 2, 255}, 10, 4, 12, false},
		{"39 first range", 9, []byte{2, 3, 2, 255}, 10, 0, 10, false},
		{"310 latter half", 10, []byte{2, 0, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1}, 10, 10, 15, false},
		{"310 no line", 10, []byte{2, 0, 2, 128}, 10, 2, 0, true},
		{"310 past the table", 10, []byte{2, 1}, 10, 2, 0, true},
		{"odd table", 10, []byte{2}, 10, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := pythonLegacyLine(tc.minor, tc.table, tc.first, tc.pos)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, line)
		})
	}
}

func TestDecodePythonMessage(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind uint8
		data []byte
		want string
	}{
		{"ASCII", 1, []byte("hello"), "hello"},
		{"Latin1", 1, []byte{0xe9}, "é"},
		{"UCS2", 2, []byte{0x2d, 0x4e}, "中"},
		{"UCS4", 4, []byte{0x42, 0xf6, 1, 0}, "🙂"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodePythonMessage(tc.data, tc.kind)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := decodePythonMessage([]byte{1, 2, 3}, 2)
	require.Error(t, err)
	_, err = decodePythonMessage([]byte{0, 0xd8}, 2)
	require.Error(t, err, "lone surrogates are not valid UTF-8")
}

// fakePythonProcess lays out CPython 3.12 objects in a flat address space.
type fakePythonProcess struct {
	memory []byte
	next   uint64
}

const (
	fakeBase           = 0x1000
	fakeASCIIData      = 40
	fakeCompactData    = 56
	fakeCodeFilename   = 112
	fakeCodeName       = 128
	fakeCodeLinetable  = 136
	fakeCodeFirstline  = 68
	fakeCodeHeaderSize = 144
)

func newFakePythonProcess() *fakePythonProcess {
	return &fakePythonProcess{memory: make([]byte, 0x20000), next: fakeBase}
}

func (p *fakePythonProcess) alloc(size uint64) (uint64, []byte) {
	address := p.next
	p.next += (size + 15) &^ 15
	return address, p.memory[address : address+size]
}

func (p *fakePythonProcess) str(text string) uint64 {
	address, object := p.alloc(fakeASCIIData + uint64(len(text)))
	binary.LittleEndian.PutUint64(object[pythonUnicodeLengthOffset:], uint64(len(text)))
	binary.LittleEndian.PutUint32(object[pythonUnicodeStateOffset:], 1<<pythonUnicodeKindShift|pythonUnicodeCompact|pythonUnicodeASCII)
	copy(object[fakeASCIIData:], text)
	return address
}

func (p *fakePythonProcess) code(file, function string, firstLine uint32, table []byte) uint64 {
	lineTable, bytesObject := p.alloc(pythonBytesDataOffset + uint64(len(table)))
	binary.LittleEndian.PutUint64(bytesObject[pythonBytesSizeOffset:], uint64(len(table)))
	copy(bytesObject[pythonBytesDataOffset:], table)

	address, object := p.alloc(fakeCodeHeaderSize)
	binary.LittleEndian.PutUint64(object[fakeCodeFilename:], p.str(file))
	binary.LittleEndian.PutUint64(object[fakeCodeName:], p.str(function))
	binary.LittleEndian.PutUint64(object[fakeCodeLinetable:], lineTable)
	binary.LittleEndian.PutUint32(object[fakeCodeFirstline:], firstLine)
	return address
}

// fakeTypeSize covers the 3.12 PyHeapTypeObject up to ht_qualname.
const fakeTypeSize = 880

func (p *fakePythonProcess) exceptionType(name string) uint64 {
	nameAddress, text := p.alloc(uint64(len(name)) + 1)
	copy(text, name)
	address, object := p.alloc(fakeTypeSize)
	binary.LittleEndian.PutUint64(object[pythonTypeNameOffset:], nameAddress)
	return address
}

// heapType is a class defined in Python, whose module is in its __dict__.
func (p *fakePythonProcess) heapType(name, qualname, module string) uint64 {
	address := p.exceptionType(name)
	object := p.memory[address : address+fakeTypeSize]
	binary.LittleEndian.PutUint64(object[pythonTypeFlagsOffset:], pythonTypeFlagHeapType)
	binary.LittleEndian.PutUint64(object[pythonHeapTypeQualname[12]:], p.str(qualname))

	// a DICT_KEYS_UNICODE table with 8 one-byte indices and two entries
	keys, table := p.alloc(pythonKeysIndicesOffset + 8 + 2*16)
	table[pythonKeysIndexBytesLog2] = 3
	table[pythonKeysKindOffset] = 1
	binary.LittleEndian.PutUint64(table[pythonKeysEntriesCount:], 2)
	entries := table[pythonKeysIndicesOffset+8:]
	binary.LittleEndian.PutUint64(entries[0:], p.str("__doc__"))
	binary.LittleEndian.PutUint64(entries[8:], p.str("documented"))
	binary.LittleEndian.PutUint64(entries[16:], p.str("__module__"))
	binary.LittleEndian.PutUint64(entries[24:], p.str(module))
	dict, dictObject := p.alloc(48)
	binary.LittleEndian.PutUint64(dictObject[pythonDictKeysOffset:], keys)
	binary.LittleEndian.PutUint64(object[pythonTypeDictOffset:], dict)
	return address
}

func (p *fakePythonProcess) remote() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{ReaderAt: bytes.NewReader(p.memory)}
}

func fakePythonRecord(exceptionType uint64, message string, frames ...uint64) *BpfPythonExceptionPayloadT {
	record := &BpfPythonExceptionPayloadT{Type: exceptionType, FrameCount: uint8(len(frames))}
	record.Layout.Minor = 12
	record.Layout.CodeFilename = fakeCodeFilename
	record.Layout.CodeName = fakeCodeName
	record.Layout.CodeLinetable = fakeCodeLinetable
	record.Layout.CodeFirstlineno = fakeCodeFirstline
	record.Layout.UnicodeAsciiData = fakeASCIIData
	record.Layout.UnicodeCompactData = fakeCompactData
	if message != "" {
		record.Message.Count = 1
		record.Message.Kind[0] = BpfPythonExceptionArgKindK_pythonArgStr1
		record.Message.Len[0] = uint16(copy(record.Text[:], message))
	}
	for i, code := range frames {
		record.Frames[i].Code = code
	}
	return record
}

func TestDescribePythonException(t *testing.T) {
	process := newFakePythonProcess()
	valueError := process.exceptionType("ValueError")
	// each table maps code unit 0 to its first line plus the delta
	leaf := process.code("/app/server.py", "leaf", 40, []byte{216, 1, 2})
	handler := process.code("/app/server.py", "get", 10, []byte{128, 0})
	shim := process.code("<shim>", "__init__", 1, []byte{248})

	event := exceptions.Event{}
	record := fakePythonRecord(valueError, "boom", leaf, shim, handler, 0x42)
	require.NoError(t, describePythonException(process.remote(), record, &event))

	assert.Equal(t, "ValueError", event.Type)
	assert.Equal(t, "boom", event.Message)
	assert.Equal(t, int32(plog.SeverityNumberError), event.SeverityNumber)
	assert.Equal(t, "Traceback (most recent call last):\n"+
		"  File \"<unknown>\", line 0, in <unknown>\n"+
		"  File \"/app/server.py\", line 10, in get\n"+
		"  File \"/app/server.py\", line 41, in leaf\n"+
		"ValueError: boom\n", event.Stacktrace)
}

func TestDescribePythonRecursion(t *testing.T) {
	process := newFakePythonProcess()
	recurse := process.code("/app/server.py", "recurse", 30, []byte{128, 0})
	raise := process.code("/app/server.py", "recurse", 29, []byte{128, 0})
	handler := process.code("/app/server.py", "get", 10, []byte{128, 0})
	// innermost first: the raising frame, five recursive calls, the handler
	record := fakePythonRecord(process.exceptionType("RecursionError"), "deep",
		raise, recurse, recurse, recurse, recurse, recurse, handler)
	record.Flags = BpfPythonExceptionFlagsK_pythonExceptionTruncated

	event := exceptions.Event{}
	require.NoError(t, describePythonException(process.remote(), record, &event))
	assert.Equal(t, "Traceback (most recent call last):\n"+
		"  ... frames omitted\n"+
		"  File \"/app/server.py\", line 10, in get\n"+
		"  File \"/app/server.py\", line 30, in recurse\n"+
		"  File \"/app/server.py\", line 30, in recurse\n"+
		"  File \"/app/server.py\", line 30, in recurse\n"+
		"  [Previous line repeated 2 more times]\n"+
		"  File \"/app/server.py\", line 29, in recurse\n"+
		"RecursionError: deep\n", event.Stacktrace)
}

func TestDescribePythonExceptionType(t *testing.T) {
	process := newFakePythonProcess()
	for _, tc := range []struct {
		name, message, wantType, wantMessage, wantLast string
		object                                         uint64
		truncated                                      bool
	}{
		{"builtin", "boom", "ValueError", "boom", "ValueError: boom", process.exceptionType("ValueError"), false},
		{"extension", "", "decimal.InvalidOperation", "", "decimal.InvalidOperation", process.exceptionType("decimal.InvalidOperation"), false},
		{
			"class", "declined", "cases.Billing.Declined", "declined", "cases.Billing.Declined: declined",
			process.heapType("Declined", "Billing.Declined", "cases"), false,
		},
		{"main class", "x", "__main__.CustomError", "x", "CustomError: x", process.heapType("CustomError", "CustomError", "__main__"), false},
		{"key error", "user_id", "KeyError", "'user_id'", "KeyError: 'user_id'", process.exceptionType("KeyError"), false},
		{"truncated", "aaaa", "ValueError", "aaaa...", "ValueError: aaaa...", process.exceptionType("ValueError"), true},
		{"truncated key", "aaaa", "KeyError", "'aaaa...", "KeyError: 'aaaa...", process.exceptionType("KeyError"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := fakePythonRecord(tc.object, tc.message)
			if tc.truncated {
				record.Message.Truncated = 1
			}
			event := exceptions.Event{}
			require.NoError(t, describePythonException(process.remote(), record, &event))
			assert.Equal(t, tc.wantType, event.Type)
			assert.Equal(t, tc.wantMessage, event.Message)
			assert.Equal(t, "Traceback (most recent call last):\n"+tc.wantLast+"\n", event.Stacktrace)
		})
	}
}

func TestPythonRepr(t *testing.T) {
	for text, want := range map[string]string{
		"user_id":   `'user_id'`,
		"it's":      `"it's"`,
		`it's "x"`:  `'it\'s "x"'`,
		"a\tb\nc\\": `'a\tb\nc\\'`,
		"\x00\x7f":  `'\x00\x7f'`,
		"café 東京 🐍": `'café 東京 🐍'`,
		"\u200b":    `'\u200b'`,
	} {
		assert.Equal(t, want, pythonRepr(text), text)
	}
}

func TestDescribePython310Frame(t *testing.T) {
	process := newFakePythonProcess()
	// (2 bytes, +0 lines), (2 bytes, +3 lines): code unit 1 is byte 2, in the second range
	handler := process.code("/app/legacy.py", "handler", 20, []byte{2, 0, 2, 3})
	record := fakePythonRecord(process.exceptionType("KeyError"), "", handler)
	record.Layout.Minor = 10
	record.Frames[0].Instr = 1

	event := exceptions.Event{}
	require.NoError(t, describePythonException(process.remote(), record, &event))
	assert.Equal(t, "Traceback (most recent call last):\n  File \"/app/legacy.py\", line 23, in handler\nKeyError\n", event.Stacktrace)
}

func TestDescribePythonTruncatedException(t *testing.T) {
	process := newFakePythonProcess()
	record := fakePythonRecord(process.exceptionType("RuntimeError"), "startup failed")
	record.Flags = BpfPythonExceptionFlagsK_pythonExceptionTruncated

	event := exceptions.Event{}
	require.NoError(t, describePythonException(process.remote(), record, &event))
	assert.Equal(t, int32(plog.SeverityNumberError), event.SeverityNumber)
	assert.Equal(t, "Traceback (most recent call last):\n  ... frames omitted\nRuntimeError: startup failed\n", event.Stacktrace)
}

func TestDescribePythonExceptionWithSurrogateMessage(t *testing.T) {
	process := newFakePythonProcess()
	handler := process.code("/app/server.py", "get", 10, []byte{128, 0})
	record := fakePythonRecord(process.exceptionType("ValueError"), "", handler)
	record.Message.Count = 1
	record.Message.Kind[0] = BpfPythonExceptionArgKindK_pythonArgStr2
	record.Message.Len[0] = 2
	record.Text[0], record.Text[1] = 0, 0xd8

	event := exceptions.Event{}
	require.NoError(t, describePythonException(process.remote(), record, &event))
	assert.Equal(t, "ValueError", event.Type)
	assert.Empty(t, event.Message)
	assert.Equal(t, "Traceback (most recent call last):\n"+
		"  File \"/app/server.py\", line 10, in get\nValueError\n", event.Stacktrace)

	record.Type = 0x42
	event = exceptions.Event{}
	require.Error(t, describePythonException(process.remote(), record, &event))
}

func TestDescribePythonExceptionNeedsTypeOrMessage(t *testing.T) {
	process := newFakePythonProcess()
	event := exceptions.Event{}
	require.Error(t, describePythonException(process.remote(), fakePythonRecord(0x42, ""), &event))

	require.NoError(t, describePythonException(process.remote(), fakePythonRecord(0x42, "only a message"), &event))
	assert.Empty(t, event.Type)
	assert.Equal(t, "only a message", event.Message)
}

func TestParsePythonExceptionPayload(t *testing.T) {
	encode := func(record *BpfPythonExceptionPayloadT) []byte {
		var buf bytes.Buffer
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, record))
		return buf.Bytes()[:pythonFramesOffset+int(record.FrameCount)*pythonFrameSize]
	}

	record := fakePythonRecord(0x10, "message", 0x100, 0x200)
	parsed, err := parsePythonExceptionPayload(encode(record))
	require.NoError(t, err)
	assert.Equal(t, record.Frames[:2], parsed.Frames[:2])
	assert.Equal(t, "message", string(parsed.Text[:parsed.Message.Len[0]]))

	_, err = parsePythonExceptionPayload(encode(record)[:pythonFramesOffset+pythonFrameSize])
	require.ErrorIs(t, err, errPythonExceptionPayload, "a payload shorter than its frames")

	for name, corrupt := range map[string]func(*BpfPythonExceptionPayloadT){
		"message length": func(r *BpfPythonExceptionPayloadT) { r.Message.Len[0] = uint16(len(r.Text) + 1) },
		"argument part": func(r *BpfPythonExceptionPayloadT) {
			r.Message.Count = 2
			r.Message.Len[1] = uint16(len(r.Text)/len(r.Message.Len) + 1)
		},
		"argument count": func(r *BpfPythonExceptionPayloadT) { r.Message.Count = uint8(len(r.Message.Len) + 1) },
	} {
		corrupted := *record
		corrupt(&corrupted)
		_, err = parsePythonExceptionPayload(encode(&corrupted))
		require.ErrorIs(t, err, errPythonExceptionPayload, name)
	}

	_, err = parsePythonExceptionPayload(make([]byte, pythonFramesOffset-1))
	require.ErrorIs(t, err, errPythonExceptionPayload)
	assert.Equal(t, 16, int(unsafe.Sizeof(record.Frames[0])))
}

func TestDescribePythonLegacyHeapType(t *testing.T) {
	for _, minor := range []uint8{9, 10} {
		for _, slots := range []uint64{8, 256, 65536} {
			process := newFakePythonProcess()
			process.memory = make([]byte, 1<<20)
			object := process.exceptionType("Declined")
			binary.LittleEndian.PutUint64(process.memory[object+pythonTypeFlagsOffset:], pythonTypeFlagHeapType)
			binary.LittleEndian.PutUint64(process.memory[object+pythonHeapTypeQualname[minor]:], process.str("Billing.Declined"))

			width := uint64(1)
			switch slots {
			case 256:
				width = 2
			case 65536:
				width = 4
			}
			// CPython 3.9/3.10: five pointer-sized header fields, indices,
			// then PyDictKeyEntry {hash, key, value}.
			keys, table := process.alloc(40 + slots*width + 24)
			binary.LittleEndian.PutUint64(table[8:], slots)
			binary.LittleEndian.PutUint64(table[32:], 1)
			entry := table[40+slots*width:]
			binary.LittleEndian.PutUint64(entry[8:], process.str("__module__"))
			binary.LittleEndian.PutUint64(entry[16:], process.str("payments"))
			dict, dictObject := process.alloc(48)
			binary.LittleEndian.PutUint64(dictObject[pythonDictKeysOffset:], keys)
			binary.LittleEndian.PutUint64(process.memory[object+pythonTypeDictOffset:], dict)

			record := fakePythonRecord(object, "declined")
			record.Layout.Minor = minor
			event := exceptions.Event{}
			require.NoError(t, describePythonException(process.remote(), record, &event))
			assert.Equal(t, "payments.Billing.Declined", event.Type)
			assert.Contains(t, event.Stacktrace, "payments.Billing.Declined: declined")

			binary.LittleEndian.PutUint64(table[32:], pythonMaxDictEntries+1)
			_, err := pythonDictString(process.remote(), record, dict, "__module__")
			require.ErrorIs(t, err, errPythonObject)
		}
	}
}

// fakePythonArgs stores arguments as the probe does: one fills the buffer,
// several take equal parts of it.
func fakePythonArgs(message *BpfPythonExceptionMessageT, text []byte, args ...any) {
	fakePythonPartialArgs(message, text, false, args...)
}

// fakePythonPartialArgs stores arguments followed, when `more` is set, by
// ones the probe did not record.
func fakePythonPartialArgs(message *BpfPythonExceptionMessageT, text []byte, more bool, args ...any) {
	*message = BpfPythonExceptionMessageT{Count: uint8(len(args))}
	if more {
		message.More = 1
	}
	part := pythonArgCapacity(message, len(text))
	for i, arg := range args {
		var data []byte
		switch arg := arg.(type) {
		case string:
			message.Kind[i] = BpfPythonExceptionArgKindK_pythonArgStr1
			data = []byte(arg)
		case []byte:
			message.Kind[i] = BpfPythonExceptionArgKindK_pythonArgInt
			data = arg
		}
		message.Len[i] = uint16(copy(text[i*part:][:part], data))
	}
}

// pythonLong encodes an int as CPython 3.11 (ob_size) or 3.12+ (lv_tag) stores it.
func pythonLong(minor uint8, negative bool, digits ...uint32) []byte {
	data := make([]byte, pythonLongValueSize+len(digits)*pythonLongDigitSize)
	count := uint64(len(digits))
	word := count
	switch {
	case minor >= pythonLongTaggedMinor:
		word = count << pythonLongTagShift
		if negative {
			word |= pythonLongSignNegative
		} else if count == 0 {
			word |= 1
		}
	case negative:
		word = uint64(-int64(count))
	}
	binary.LittleEndian.PutUint64(data, word)
	for i, digit := range digits {
		binary.LittleEndian.PutUint32(data[pythonLongValueSize+i*pythonLongDigitSize:], digit)
	}
	return data
}

func TestPythonMessageArguments(t *testing.T) {
	for _, minor := range []uint8{11, 12} {
		for _, tc := range []struct {
			name, qualname, want string
			args                 []any
			truncated            uint8
			more                 bool
		}{
			{"int", "ValueError", "404", []any{pythonLong(minor, false, 404)}, 0, false},
			{"zero", "SystemExit", "0", []any{pythonLong(minor, false)}, 0, false},
			{"negative", "ValueError", "-7", []any{pythonLong(minor, true, 7)}, 0, false},
			// 2**30 + 5 spans two 30-bit digits
			{"two digits", "ValueError", "1073741829", []any{pythonLong(minor, false, 5, 1)}, 0, false},
			{"key error int", "KeyError", "404", []any{pythonLong(minor, false, 404)}, 0, false},
			{"tuple", "Exception", "('first', 2)", []any{"first", pythonLong(minor, false, 2)}, 0, false},
			{"key error tuple", "KeyError", "('a', 'b')", []any{"a", "b"}, 0, false},
			{"truncated tuple", "Exception", "('first', 'sec...", []any{"first", "sec", "third"}, 2, false},
			{"truncated last", "Exception", "('first', 'sec...", []any{"first", "sec"}, 2, false},
			{"unsupported argument", "ValueError", "('invalid order id', ...", []any{"invalid order id"}, 0, true},
			{"more than stored", "Exception", "('a', 'b', 'c', 'd', ...", []any{"a", "b", "c", "d"}, 0, true},
			{"truncated before more", "Exception", "('first', 'sec...", []any{"first", "sec"}, 2, true},
		} {
			t.Run(fmt.Sprintf("3.%d/%s", minor, tc.name), func(t *testing.T) {
				var message BpfPythonExceptionMessageT
				text := make([]byte, 256)
				fakePythonPartialArgs(&message, text, tc.more, tc.args...)
				message.Truncated = tc.truncated
				assert.Equal(t, tc.want, pythonMessage("builtins", tc.qualname, &message, text, minor))
			})
		}
	}

	var message BpfPythonExceptionMessageT
	text := make([]byte, 256)
	fakePythonArgs(&message, text, pythonLong(12, false, 1, 2))
	message.Len[0] -= pythonLongDigitSize
	assert.Empty(t, pythonMessage("builtins", "ValueError", &message, text, 12), "digits missing from the stored int")
	fakePythonArgs(&message, text, "a", []byte{1})
	assert.Empty(t, pythonMessage("builtins", "ValueError", &message, text, 12), "a short int")
}
