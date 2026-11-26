// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"

	"go.opentelemetry.io/obi/pkg/exceptions"
)

func init() {
	RegisterExceptionPayloadDecoder(BpfExceptionRuntimeK_exceptionRuntimePython, decodePythonException)
}

// ShrinkPythonExceptionMaps avoids allocating capture state nobody uses. The
// generic and Go tracers share these internal maps, so both must call it.
func ShrinkPythonExceptionMaps(spec *ebpf.CollectionSpec) {
	for _, name := range []string{"python_exception_procs", "python_exception_pending"} {
		if m := spec.Maps[name]; m != nil {
			m.MaxEntries = 1
		}
	}
}

// ABI-stable CPython object offsets on 64-bit builds.
const (
	pythonTypeNameOffset      = 24
	pythonBytesSizeOffset     = 16
	pythonBytesDataOffset     = 32
	pythonUnicodeLengthOffset = 16
	pythonUnicodeStateOffset  = 32

	pythonUnicodeKindShift = 2
	pythonUnicodeKindMask  = 7
	pythonUnicodeCompact   = 1 << 5
	pythonUnicodeASCII     = 1 << 6

	pythonMaxString    = 4096
	pythonMaxLineTable = 1 << 16

	// traceback folds a frame repeated more than this many times in a row.
	pythonRecursiveCutoff = 3
)

// PyLongObject: ob_size, or lv_tag on 3.12+, then 30-bit digits in u32s.
const (
	pythonLongValueSize    = 8
	pythonLongDigitSize    = 4
	pythonLongShift        = 30
	pythonLongTaggedMinor  = 12
	pythonLongTagShift     = 3
	pythonLongSignMask     = 3
	pythonLongSignNegative = 2
)

// CPython 3.11+ type and dict layout, the same on every 3.11-3.14 build; the
// heap type's __qualname__ moved in 3.12. Python classes on 3.9 and 3.10 keep
// their __name__.
const (
	pythonTypeFlagsOffset        = 168
	pythonTypeDictOffset         = 264
	pythonTypeFlagHeapType       = 1 << 9
	pythonDictKeysOffset         = 32
	pythonDictValuesOffset       = 40
	pythonKeysIndexBytesLog2     = 9
	pythonKeysKindOffset         = 10
	pythonKeysEntriesCount       = 24
	pythonKeysIndicesOffset      = 32
	pythonKeysHeaderSize         = 32
	pythonLegacyKeysHeaderSize   = 40
	pythonLegacyKeysSize         = 8
	pythonLegacyKeysEntriesCount = 32
	pythonMaxDictEntries         = 1024
	pythonDictKeyEntrySize       = 24
	pythonDictKeyEntryKeyOffset  = 8
	pythonDictUnicodeEntrySize   = 16
)

var pythonHeapTypeQualname = map[uint8]uint64{9: 856, 10: 864, 11: 864, 12: 872, 13: 872, 14: 872}

var (
	errPythonExceptionPayload = errors.New("invalid Python exception payload")
	errPythonObject           = errors.New("unreadable Python object")
	// a code range CPython marks as having no source line, such as the
	// _Py_InitCleanup shim frame on 3.13+, which traceback leaves out
	errPythonNoLocation = errors.New("python code without a source location")
)

const pythonFramesOffset = int(unsafe.Offsetof(BpfPythonExceptionPayloadT{}.Frames))

var pythonFrameSize = int(unsafe.Sizeof(BpfPythonExceptionPayloadT{}.Frames[0]))

// decodePythonException reads the type name and the frames' code objects from
// the raising process and formats a CPython-style traceback.
func decodePythonException(payload []byte, event *exceptions.Event) error {
	record, err := parsePythonExceptionPayload(payload)
	if err != nil {
		return err
	}
	return describePythonException(remotememory.NewProcessVirtualMemory(libpf.PID(record.ObiPid)), record, event)
}

func describePythonException(memory remotememory.RemoteMemory, record *BpfPythonExceptionPayloadT, event *exceptions.Event) error {
	module, qualname := pythonTypeName(memory, record)
	event.Type = pythonQualifiedName(module, qualname, "builtins")
	event.Message = pythonMessage(module, qualname, &record.Message, record.Text[:], record.Layout.Minor)
	if event.Type == "" && event.Message == "" {
		return fmt.Errorf("%w: unreadable type", errPythonExceptionPayload)
	}

	event.Stacktrace = pythonTraceback(memory, record) + pythonExceptionLine(module, qualname, event.Message)
	event.SeverityNumber = int32(plog.SeverityNumberError)
	return nil
}

// pythonExceptionLine is the line traceback ends an exception with.
func pythonExceptionLine(module, qualname, message string) string {
	line := pythonQualifiedName(module, qualname, "builtins", "__main__")
	if message != "" {
		if line != "" {
			line += ": "
		}
		line += message
	}
	return line + "\n"
}

// pythonTypeName returns a type's __module__ and __qualname__. A static type
// names its module in tp_name, as "module.Name", and builtins have none.
func pythonTypeName(memory remotememory.RemoteMemory, record *BpfPythonExceptionPayloadT) (string, string) {
	layout, object := &record.Layout, record.Type
	name := memory.StringPtr(libpf.Address(object + pythonTypeNameOffset))
	flags := memory.Uint64(libpf.Address(object + pythonTypeFlagsOffset))
	qualnameOffset, known := pythonHeapTypeQualname[layout.Minor]
	if flags&pythonTypeFlagHeapType == 0 {
		if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
			return name[:dot], name[dot+1:]
		}
		return "builtins", name
	}
	if !known {
		return "", name
	}

	qualname, err := pythonString(memory, layout.UnicodeAsciiData, layout.UnicodeCompactData,
		memory.Uint64(libpf.Address(object+qualnameOffset)))
	if err != nil {
		return "", name
	}
	dict := memory.Uint64(libpf.Address(object + pythonTypeDictOffset))
	module, err := pythonDictString(memory, record, dict, "__module__")
	if err != nil {
		return "", qualname
	}
	return module, qualname
}

// pythonDictString returns the str stored under a str key of a combined-table dict.
func pythonDictString(memory remotememory.RemoteMemory, record *BpfPythonExceptionPayloadT, dict uint64, key string) (string, error) {
	if dict == 0 || memory.Uint64(libpf.Address(dict+pythonDictValuesOffset)) != 0 {
		return "", errPythonObject
	}
	keys := memory.Uint64(libpf.Address(dict + pythonDictKeysOffset))
	headerSize := pythonKeysHeaderSize
	if record.Layout.Minor < 11 {
		headerSize = pythonLegacyKeysHeaderSize
	}
	header := make([]byte, headerSize)
	if keys == 0 || memory.Read(libpf.Address(keys), header) != nil {
		return "", errPythonObject
	}

	count, indexBytes, size, keyOffset, err := pythonDictEntries(header, record.Layout.Minor)
	if err != nil {
		return "", err
	}
	entries := make([]byte, count*size)
	if err := memory.Read(libpf.Address(keys+uint64(headerSize)+indexBytes), entries); err != nil {
		return "", err
	}
	ascii, compact := record.Layout.UnicodeAsciiData, record.Layout.UnicodeCompactData
	for entry := range slices.Chunk(entries, int(size)) {
		name, err := pythonString(memory, ascii, compact, binary.LittleEndian.Uint64(entry[keyOffset:]))
		if err == nil && name == key {
			return pythonString(memory, ascii, compact, binary.LittleEndian.Uint64(entry[keyOffset+8:]))
		}
	}
	return "", errPythonObject
}

// pythonDictEntries locates entries after the variable-width index array.
// Before 3.11, dk_size counts slots and every entry includes a hash.
func pythonDictEntries(header []byte, minor uint8) (count, indexBytes, size uint64, keyOffset int, err error) {
	size, keyOffset = pythonDictKeyEntrySize, pythonDictKeyEntryKeyOffset
	if minor < 11 {
		slots := binary.LittleEndian.Uint64(header[pythonLegacyKeysSize:])
		count = binary.LittleEndian.Uint64(header[pythonLegacyKeysEntriesCount:])
		if slots == 0 || slots&(slots-1) != 0 || slots > 1<<32 {
			return 0, 0, 0, 0, errPythonObject
		}
		width := uint64(1)
		if slots > 0xff {
			width = 2
		}
		if slots > 0xffff {
			width = 4
		}
		if slots > 0xffffffff {
			width = 8
		}
		indexBytes = slots * width
	} else {
		indexBytesLog2 := header[pythonKeysIndexBytesLog2]
		count = binary.LittleEndian.Uint64(header[pythonKeysEntriesCount:])
		if indexBytesLog2 > 32 {
			return 0, 0, 0, 0, errPythonObject
		}
		indexBytes = uint64(1) << indexBytesLog2
		// DICT_KEYS_UNICODE omits the hash field.
		if header[pythonKeysKindOffset] != 0 {
			size, keyOffset = pythonDictUnicodeEntrySize, 0
		}
	}
	if count > pythonMaxDictEntries {
		return 0, 0, 0, 0, errPythonObject
	}
	return count, indexBytes, size, keyOffset, nil
}

// pythonQualifiedName prefixes the module, unless it is one of `implicit`.
func pythonQualifiedName(module, qualname string, implicit ...string) string {
	if module == "" || slices.Contains(implicit, module) {
		return qualname
	}
	return module + "." + qualname
}

// pythonMessage renders the stored arguments as str() does: one argument as
// itself, a KeyError's str key quoted, and several as their tuple. A str cut
// by the probe, or arguments it did not record, end the message in "...".
func pythonMessage(module, qualname string, message *BpfPythonExceptionMessageT, text []byte, minor uint8) string {
	count := int(message.Count)
	if count == 0 {
		return ""
	}
	part := pythonArgCapacity(message, len(text))
	tuple := pythonArgsTuple(message)
	quote := tuple || (module == "builtins" && qualname == "KeyError")

	args := make([]string, 0, count+1)
	for i := range count {
		data := text[i*part:][:message.Len[i]]
		arg, err := pythonArg(message.Kind[i], data, minor, quote)
		if err != nil {
			return ""
		}
		if message.Truncated&(1<<i) != 0 {
			if quote {
				arg = arg[:len(arg)-1]
			}
			args = append(args, arg+"...")
			return pythonArgs(args, tuple, false)
		}
		args = append(args, arg)
	}
	if message.More != 0 {
		return pythonArgs(append(args, "..."), tuple, false)
	}
	return pythonArgs(args, tuple, true)
}

// pythonArgsTuple reports whether str() renders the arguments as their tuple.
func pythonArgsTuple(message *BpfPythonExceptionMessageT) bool {
	return message.Count > 1 || message.More != 0
}

// pythonArgCapacity is the buffer part of each argument: all of it for a lone one.
func pythonArgCapacity(message *BpfPythonExceptionMessageT, size int) int {
	if !pythonArgsTuple(message) {
		return size
	}
	return size / len(message.Len)
}

// pythonArgs joins several arguments as their tuple; a cut one ends it.
func pythonArgs(args []string, tuple, complete bool) string {
	if !tuple {
		return args[0]
	}
	text := "(" + strings.Join(args, ", ")
	if complete {
		text += ")"
	}
	return text
}

func pythonArg(kind BpfPythonExceptionArgKind, data []byte, minor uint8, quote bool) (string, error) {
	if kind == BpfPythonExceptionArgKindK_pythonArgInt {
		return pythonInt(data, minor)
	}
	text, err := decodePythonMessage(data, uint8(kind))
	if err != nil || !quote {
		return text, err
	}
	return pythonRepr(text), nil
}

// pythonInt formats an int stored as its ob_size, or 3.12+ lv_tag, and digits.
func pythonInt(data []byte, minor uint8) (string, error) {
	if len(data) < pythonLongValueSize || (len(data)-pythonLongValueSize)%pythonLongDigitSize != 0 {
		return "", errPythonObject
	}
	word := binary.LittleEndian.Uint64(data)
	digits := data[pythonLongValueSize:]
	count := uint64(len(digits) / pythonLongDigitSize)

	var negative bool
	var stored uint64
	if minor >= pythonLongTaggedMinor {
		negative = word&pythonLongSignMask == pythonLongSignNegative
		stored = word >> pythonLongTagShift
	} else {
		size := int64(word)
		negative = size < 0
		stored = uint64(max(size, -size))
	}
	if stored != count {
		return "", errPythonObject
	}

	value := new(big.Int)
	for i := len(digits) - pythonLongDigitSize; i >= 0; i -= pythonLongDigitSize {
		value.Lsh(value, pythonLongShift)
		value.Or(value, big.NewInt(int64(binary.LittleEndian.Uint32(digits[i:]))))
	}
	if negative {
		value.Neg(value)
	}
	return value.String(), nil
}

// pythonRepr quotes a str as Python's repr() does.
func pythonRepr(text string) string {
	quote := '\''
	if strings.ContainsRune(text, '\'') && !strings.ContainsRune(text, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteRune(quote)
	for _, r := range text {
		switch {
		case r == quote || r == '\\':
			b.WriteRune('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r < 0x100:
			b.WriteString(`\x` + pythonHex(r, 2))
		case r < 0x10000:
			b.WriteString(`\u` + pythonHex(r, 4))
		default:
			b.WriteString(`\U` + pythonHex(r, 8))
		}
	}
	b.WriteRune(quote)
	return b.String()
}

func pythonHex(r rune, digits int) string {
	hex := strconv.FormatInt(int64(r), 16)
	return strings.Repeat("0", digits-len(hex)) + hex
}

func parsePythonExceptionPayload(payload []byte) (*BpfPythonExceptionPayloadT, error) {
	if len(payload) < pythonFramesOffset {
		return nil, errPythonExceptionPayload
	}
	full := make([]byte, unsafe.Sizeof(BpfPythonExceptionPayloadT{}))
	copy(full, payload)
	record := &BpfPythonExceptionPayloadT{}
	if err := binary.Read(bytes.NewReader(full), binary.LittleEndian, record); err != nil {
		return nil, err
	}
	if int(record.FrameCount) > len(record.Frames) ||
		len(payload) != pythonFramesOffset+int(record.FrameCount)*pythonFrameSize ||
		!pythonMessageFits(&record.Message, len(record.Text)) {
		return nil, errPythonExceptionPayload
	}
	return record, nil
}

func pythonMessageFits(message *BpfPythonExceptionMessageT, size int) bool {
	count := int(message.Count)
	if count > len(message.Len) {
		return false
	}
	part := pythonArgCapacity(message, size)
	for _, length := range message.Len[:count] {
		if int(length) > part {
			return false
		}
	}
	return true
}

// pythonTraceback writes the frames outermost first, as traceback.format_exception
// does, without source lines.
func pythonTraceback(memory remotememory.RemoteMemory, record *BpfPythonExceptionPayloadT) string {
	var traceback strings.Builder
	traceback.WriteString("Traceback (most recent call last):\n")
	if record.Flags&BpfPythonExceptionFlagsK_pythonExceptionTruncated != 0 {
		traceback.WriteString("  ... frames omitted\n")
	}

	var last string
	repeated := 0
	for i := int(record.FrameCount) - 1; i >= 0; i-- {
		frame := record.Frames[i]
		file, line, function, err := pythonFrame(memory, record, frame.Code, frame.Instr)
		if errors.Is(err, errPythonNoLocation) {
			continue
		}
		entry := "  File \"<unknown>\", line 0, in <unknown>\n"
		if err == nil {
			entry = fmt.Sprintf("  File \"%s\", line %d, in %s\n", file, line, function)
		}
		if entry != last {
			pythonRepeated(&traceback, repeated)
			last, repeated = entry, 0
		}
		repeated++
		if repeated <= pythonRecursiveCutoff {
			traceback.WriteString(entry)
		}
	}
	pythonRepeated(&traceback, repeated)
	return traceback.String()
}

// pythonRepeated folds the repeats of a frame beyond the first three, as
// traceback does for recursion.
func pythonRepeated(traceback *strings.Builder, repeated int) {
	if repeated <= pythonRecursiveCutoff {
		return
	}
	more := repeated - pythonRecursiveCutoff
	plural := "s"
	if more == 1 {
		plural = ""
	}
	fmt.Fprintf(traceback, "  [Previous line repeated %d more time%s]\n", more, plural)
}

func pythonFrame(memory remotememory.RemoteMemory, record *BpfPythonExceptionPayloadT, code uint64, instr uint32) (string, uint32, string, error) {
	layout := &record.Layout
	header := make([]byte, int(max(layout.CodeFilename, layout.CodeName, layout.CodeLinetable, layout.CodeFirstlineno))+8)
	if err := memory.Read(libpf.Address(code), header); err != nil {
		return "", 0, "", err
	}
	pointer := func(offset uint8) uint64 { return binary.LittleEndian.Uint64(header[offset:]) }

	file, err := pythonString(memory, layout.UnicodeAsciiData, layout.UnicodeCompactData, pointer(layout.CodeFilename))
	if err != nil {
		return "", 0, "", err
	}
	function, err := pythonString(memory, layout.UnicodeAsciiData, layout.UnicodeCompactData, pointer(layout.CodeName))
	if err != nil {
		return "", 0, "", err
	}
	table, err := pythonBytes(memory, pointer(layout.CodeLinetable))
	if err != nil {
		return "", 0, "", err
	}
	first := binary.LittleEndian.Uint32(header[layout.CodeFirstlineno:])
	if layout.Minor < 11 {
		line, err := pythonLegacyLine(layout.Minor, table, first, instr*2)
		return file, line, function, err
	}
	line, err := pythonLine(table, first, instr)
	return file, line, function, err
}

func pythonBytes(memory remotememory.RemoteMemory, object uint64) ([]byte, error) {
	size := memory.Uint64(libpf.Address(object + pythonBytesSizeOffset))
	if object == 0 || size >= pythonMaxLineTable {
		return nil, errPythonObject
	}
	data := make([]byte, size)
	return data, memory.Read(libpf.Address(object+pythonBytesDataOffset), data)
}

// pythonString reads a compact PEP 393 str; asciiData and compactData locate its characters.
func pythonString(memory remotememory.RemoteMemory, asciiData, compactData uint8, object uint64) (string, error) {
	header := make([]byte, pythonUnicodeStateOffset+4)
	if object == 0 || memory.Read(libpf.Address(object), header) != nil {
		return "", errPythonObject
	}
	length := binary.LittleEndian.Uint64(header[pythonUnicodeLengthOffset:])
	state := binary.LittleEndian.Uint32(header[pythonUnicodeStateOffset:])
	if state&pythonUnicodeCompact == 0 || length > pythonMaxString {
		return "", errPythonObject
	}

	kind := uint8(state>>pythonUnicodeKindShift) & pythonUnicodeKindMask
	offset := compactData
	if state&pythonUnicodeASCII != 0 {
		offset = asciiData
	}
	data := make([]byte, length*uint64(kind))
	if err := memory.Read(libpf.Address(object+uint64(offset)), data); err != nil {
		return "", err
	}
	return decodePythonMessage(data, kind)
}

// Line table decoders taken from opentelemetry-ebpf-profiler's interpreter/python/python.go.
// TODO: Reuse upstream decoders once a public API supports the validation and line semantics needed here.

// pythonLine maps a code-unit offset to its line with the CPython 3.11+
// location table, documented in Objects/locations.md.
func pythonLine(table []byte, first, position uint32) (uint32, error) {
	line := int64(first)
	i := 0
	read := func() (uint32, error) {
		var v uint32
		for shift := uint(0); shift < 32; shift += 6 {
			if i >= len(table) {
				return 0, errPythonObject
			}
			b := table[i]
			i++
			if b&0x80 != 0 || (shift == 30 && b&63 > 3) {
				return 0, errPythonObject
			}
			v |= uint32(b&63) << shift
			if b&64 == 0 {
				return v, nil
			}
		}
		return 0, errPythonObject
	}
	var end uint32
	for i < len(table) {
		b := table[i]
		i++
		if b&128 == 0 {
			return 0, errPythonObject
		}
		end += uint32(b&7) + 1
		code := (b >> 3) & 15
		available := true
		switch {
		case code <= 9:
			if i >= len(table) || table[i]&128 != 0 {
				return 0, errPythonObject
			}
			i++
		case code <= 12:
			line += int64(code - 10)
			if i+2 > len(table) || table[i]&128 != 0 || table[i+1]&128 != 0 {
				return 0, errPythonObject
			}
			i += 2
		case code <= 14:
			v, err := read()
			if err != nil {
				return 0, err
			}
			delta := int64(v >> 1)
			if v&1 != 0 {
				delta = -delta
			}
			line += delta
			if code == 14 {
				for range 3 {
					if _, err = read(); err != nil {
						return 0, err
					}
				}
			}
		default:
			available = false
		}
		if end > position {
			if !available {
				return 0, errPythonNoLocation
			}
			if line < 0 || line > int64(^uint32(0)) {
				return 0, errPythonObject
			}
			return uint32(line), nil
		}
	}
	return 0, errPythonObject
}

// pythonLegacyLine maps a byte offset to its line with the CPython 3.9 co_lnotab
// or the 3.10 co_linetable, both documented in Objects/lnotab_notes.txt.
func pythonLegacyLine(minor uint8, table []byte, first, position uint32) (uint32, error) {
	if len(table)%2 != 0 {
		return 0, errPythonObject
	}
	line := int64(first)
	var end uint32
	for i := 0; i+1 < len(table); i += 2 {
		end += uint32(table[i])
		delta := int64(int8(table[i+1]))
		if minor == 9 {
			if end > position {
				break
			}
			line += delta
			continue
		}
		// -128 marks a range without a line.
		if delta != -128 {
			line += delta
		}
		if end > position {
			if delta == -128 {
				return 0, errPythonNoLocation
			}
			if line < 0 {
				return 0, errPythonObject
			}
			return uint32(line), nil
		}
	}
	if minor != 9 || line < 0 {
		return 0, errPythonObject
	}
	return uint32(line), nil
}

// decodePythonMessage decodes PEP 393 code units; kind is the unit width in bytes.
func decodePythonMessage(data []byte, kind uint8) (string, error) {
	if kind != 1 && kind != 2 && kind != 4 {
		return "", errors.New("invalid Python Unicode kind")
	}
	if len(data)%int(kind) != 0 {
		return "", errors.New("incomplete Python Unicode code unit")
	}
	var b strings.Builder
	for i := 0; i < len(data); i += int(kind) {
		r := rune(data[i])
		if kind == 2 {
			r = rune(binary.LittleEndian.Uint16(data[i:]))
		}
		if kind == 4 {
			r = rune(binary.LittleEndian.Uint32(data[i:]))
		}
		if !utf8.ValidRune(r) {
			return "", errors.New("invalid Python Unicode scalar")
		}
		b.WriteRune(r)
	}
	return b.String(), nil
}
