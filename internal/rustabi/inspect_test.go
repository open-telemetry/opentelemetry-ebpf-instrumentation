// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rustabi

import (
	"debug/dwarf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const fixtureEnvelope = "hyper::client::dispatch::Envelope<Request>"

func TestInspectLayouts(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		tagged                       bool
		txSome, txPtr, rxSome, rxPtr uint32
	}{
		{"sender with niche-optimized inner Option", false, 0, 80, 0, 88},
		{"explicitly tagged Option of sender", true, 80, 88, 88, 96},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := inspectFixture(t, callbackFixture{tagged: tc.tagged, noRetryOffset: 8})
			p, err := Inspect(path)
			require.NoError(t, err)
			require.Equal(t, Layouts{
				VecPtr: 16, VecLen: 0, VecCap: 8, RequestHeaders: 16,
				HeaderEntries: 24, HeaderCount: 8, BucketSize: 88,
				NamePtr: 32, NameLen: 24, ValuePtr: 72, ValueLen: 64, HTTP1: 1,
			}, p.Config)
			require.Equal(t, map[string]MessageLayout{
				fixtureEnvelope: {
					ListHead: 8, ListIndex: 16, SlotMask: 31,
					TxTag: 72, TxSome: tc.txSome, TxPointer: tc.txPtr,
					RxTag: 80, RxSome: tc.rxSome, RxPointer: tc.rxPtr, RxHeaders: 32, Request: true,
				},
			}, p.Channels)
		})
	}
}

func TestInspectRejectsInvalidCallback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		callback callbackFixture
		wantErr  string
	}{
		{"missing NoRetry sender", callbackFixture{missingNoRetrySender: true, noRetryOffset: 8}, "rust callback NoRetry sender"},
		{"inner field outside sender", callbackFixture{senderInnerOffset: 12, noRetryOffset: 8}, `field "inner" exceeds its containing type`},
		{"different sender pointer locations", callbackFixture{noRetryOffset: 16}, "rust callback variants"},
		{"different option tags with the same pointer", callbackFixture{tagged: true, noRetryOffset: 8, noRetryTag: 16}, "rust callback variants"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Inspect(inspectFixture(t, tc.callback))
			require.ErrorContains(t, err, tc.wantErr)
			require.Equal(t, Profile{}, p)
		})
	}
}

type callbackFixture struct {
	tagged                    bool
	missingNoRetrySender      bool
	senderInnerOffset         uint16
	noRetryOffset, noRetryTag uint16
}

// The fixture uses real namespace DIEs, variant parts and type references.
// Names like Some recur with different payloads, as they do in rustc output.
func inspectFixture(t *testing.T, callback callbackFixture) string {
	t.Helper()
	d := fixtureDWARF{info: []byte{0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, dieUnit}}
	word := d.entry(dieWord)
	d.info = append(d.info, 0x07, 8) // DW_ATE_unsigned
	pointer := d.entry(diePointer)
	d.ref(word)

	nonNull := d.structure("NonNull", 8, fixtureMember{"pointer", 0, pointer})
	request := d.httpRequest(word, pointer, nonNull)
	cb := d.callbackType(word, pointer, nonNull, callback)
	d.channelTypes(word, pointer, request, cb)
	d.info = append(d.info, 0) // end of the compilation unit
	binary.LittleEndian.PutUint32(d.info, uint32(len(d.info)-4))
	image := testELFImage(t, []testELFSection{
		{Name: ".comment", Data: []byte("rustc version 1.99.0 (fixture)")},
		{Name: ".debug_abbrev", Data: fixtureAbbrevs},
		{Name: ".debug_info", Data: d.info},
	})
	path := filepath.Join(t.TempDir(), "fixture.elf")
	require.NoError(t, os.WriteFile(path, image, 0o600))
	return path
}

func (d *fixtureDWARF) httpRequest(word, pointer, nonNull dwarf.Offset) dwarf.Offset {
	capacity := d.structure("Cap", 8, fixtureMember{"__0", 0, word})
	raw := d.structure("RawVecInner", 16, fixtureMember{"cap", 0, capacity}, fixtureMember{"ptr", 8, nonNull})
	buf := d.structure("RawVec", 16, fixtureMember{"inner", 0, raw})
	var vec dwarf.Offset
	d.namespace("alloc::vec", func() {
		vec = d.structure("Vec<u8, alloc::alloc::Global>", 24, fixtureMember{"len", 0, word}, fixtureMember{"buf", 8, buf})
	})
	bytes := d.structure("Bytes", 16, fixtureMember{"len", 0, word}, fixtureMember{"ptr", 8, pointer})
	customBytes := d.structure("CustomBytes", 16, fixtureMember{"bytes", 0, bytes})
	customName := d.structure("Custom", 24, fixtureMember{"__0", 8, customBytes})
	custom := d.structure("Custom", 24, fixtureMember{"__0", 0, customName})
	var repr, headers, request dwarf.Offset
	d.namespace("http::header::name", func() {
		repr = d.enum("Repr<http::header::name::Custom>", 32, 24, word, fixtureVariant{"Standard", 0, word}, fixtureVariant{"Custom", 1, custom})
	})
	key := d.structure("HeaderName", 40, fixtureMember{"inner", 8, repr})
	value := d.structure("HeaderValue", 24, fixtureMember{"inner", 8, bytes})
	d.namespace("http::header::map", func() {
		headers = d.structure("HeaderMap<http::header::value::HeaderValue>", 32, fixtureMember{"entries", 8, vec})
		d.structure("Bucket<http::header::value::HeaderValue>", 88, fixtureMember{"key", 8, key}, fixtureMember{"value", 56, value})
	})
	head := d.structure("Parts", 40, fixtureMember{"headers", 8, headers})
	d.namespace("http::request", func() {
		request = d.structure("Request<()>", 48, fixtureMember{"head", 8, head})
	})
	return request
}

func (d *fixtureDWARF) callbackType(word, pointer, nonNull dwarf.Offset, callback callbackFixture) dwarf.Offset {
	arc := d.structure("Arc", 8, fixtureMember{"ptr", 0, nonNull})
	// None is the null pointer. Some stores Arc at the same address.
	inner := d.option("Option<Arc>", 8, 0, pointer, 0, arc, 0, defaultVariant)
	sender := d.structure("Sender", 8, fixtureMember{"inner", callback.senderInnerOffset, inner})
	retrySender, noRetrySender := sender, sender
	if callback.tagged {
		d.namespace("retry", func() { retrySender = d.option("Option<Sender>", 16, 0, word, 8, sender, 0, 1) })
		d.namespace("no_retry", func() { noRetrySender = d.option("Option<Sender>", 24, callback.noRetryTag, word, 8, sender, 0, 1) })
	}
	var fields []fixtureMember
	if !callback.missingNoRetrySender {
		fields = append(fields, fixtureMember{"__0", callback.noRetryOffset, noRetrySender})
	}
	noRetry := d.structure("NoRetry", 40, fields...)
	// A childless NoRetry must not borrow the __0 member of the following Retry.
	retry := d.structure("Retry", 32, fixtureMember{"__0", 8, retrySender})
	return d.enum("Callback", 40, 0, word, fixtureVariant{"Retry", 0, retry}, fixtureVariant{"NoRetry", 1, noRetry})
}

func (d *fixtureDWARF) channelTypes(word, pointer, request, cb dwarf.Offset) {
	pair := d.structure("Pair", 104, fixtureMember{"__0", 0, request}, fixtureMember{"__1", 64, cb})
	pairOpt := d.option("Option<Pair>", 104, 64, word, 0, pair, 2, defaultVariant)

	var envelope dwarf.Offset
	d.namespace("hyper::client::dispatch", func() {
		envelope = d.structure("Envelope<Request>", 112, fixtureMember{"__0", 8, pairOpt})
	})
	d.namespace("tokio::sync::mpsc::list", func() {
		d.structure("Rx<"+fixtureEnvelope+">", 24, fixtureMember{"head", 8, pointer}, fixtureMember{"index", 16, word})
	})
	slots := d.entry(dieArray)
	d.ref(envelope)
	d.info = append(d.info, dieSubrange, 32, 0)
	values := d.structure("Values", 32*112, fixtureMember{"__0", 0, slots})
	d.namespace("tokio::sync::mpsc::block", func() {
		d.structure("Block<"+fixtureEnvelope+">", 32*112, fixtureMember{"values", 0, values})
	})

	envelopeOpt := d.option("Option<Envelope>", 120, 80, word, 8, envelope, 3, defaultVariant)
	ready := d.structure("Ready", 120, fixtureMember{"__0", 0, envelopeOpt})
	d.namespace("core::task::poll", func() {
		pending := d.structure("Pending", 120)
		d.enum("Poll<core::option::Option<"+fixtureEnvelope+">>", 120, 80, word, fixtureVariant{"Pending", 4, pending}, fixtureVariant{"Ready", defaultVariant, ready})
	})
}

type fixtureMember struct {
	name   string
	offset uint16
	typ    dwarf.Offset
}

type fixtureDWARF struct{ info []byte }

const (
	dieUnit = iota + 1
	dieNamespace
	dieWord
	diePointer
	dieStruct
	dieLeaf
	dieMember
	diePart
	dieVariant
	dieDefaultVariant
	dieArray
	dieSubrange
)

const (
	formData2  = 0x05
	formString = 0x08
	formData1  = 0x0b
	formRef4   = 0x13
)

var fixtureAbbrevs = []byte{
	dieUnit, byte(dwarf.TagCompileUnit), 1, 0, 0,
	dieNamespace, byte(dwarf.TagNamespace), 1, byte(dwarf.AttrName), formString, 0, 0,
	dieWord, byte(dwarf.TagBaseType), 0, byte(dwarf.AttrEncoding), formData1, byte(dwarf.AttrByteSize), formData1, 0, 0,
	diePointer, byte(dwarf.TagPointerType), 0, byte(dwarf.AttrType), formRef4, 0, 0,
	dieStruct, byte(dwarf.TagStructType), 1, byte(dwarf.AttrName), formString, byte(dwarf.AttrByteSize), formData2, 0, 0,
	dieLeaf, byte(dwarf.TagStructType), 0, byte(dwarf.AttrName), formString, byte(dwarf.AttrByteSize), formData2, 0, 0,
	dieMember, byte(dwarf.TagMember), 0, byte(dwarf.AttrName), formString, byte(dwarf.AttrDataMemberLoc), formData2, byte(dwarf.AttrType), formRef4, 0, 0,
	diePart, byte(dwarf.TagVariantPart), 1, byte(dwarf.AttrDiscr), formRef4, 0, 0,
	dieVariant, byte(dwarf.TagVariant), 1, byte(dwarf.AttrDiscrValue), formData1, 0, 0,
	dieDefaultVariant, byte(dwarf.TagVariant), 1, 0, 0,
	dieArray, byte(dwarf.TagArrayType), 1, byte(dwarf.AttrType), formRef4, 0, 0,
	dieSubrange, byte(dwarf.TagSubrangeType), 0, byte(dwarf.AttrCount), formData1, 0, 0,
	0,
}

func (d *fixtureDWARF) entry(code byte) dwarf.Offset {
	offset := dwarf.Offset(len(d.info))
	d.info = append(d.info, code)
	return offset
}

func (d *fixtureDWARF) name(s string) { d.info = append(append(d.info, s...), 0) }
func (d *fixtureDWARF) ref(off dwarf.Offset) {
	d.info = binary.LittleEndian.AppendUint32(d.info, uint32(off))
}

func (d *fixtureDWARF) namespace(path string, emit func()) {
	scopes := strings.Split(path, "::")
	for _, scope := range scopes {
		d.entry(dieNamespace)
		d.name(scope)
	}
	emit()
	d.info = append(d.info, make([]byte, len(scopes))...)
}

func (d *fixtureDWARF) structHeader(code byte, name string, size uint16) dwarf.Offset {
	start := d.entry(code)
	d.name(name)
	d.info = binary.LittleEndian.AppendUint16(d.info, size)
	return start
}

func (d *fixtureDWARF) member(field fixtureMember) {
	d.entry(dieMember)
	d.name(field.name)
	d.info = binary.LittleEndian.AppendUint16(d.info, field.offset)
	d.ref(field.typ)
}

func (d *fixtureDWARF) structure(name string, size uint16, fields ...fixtureMember) dwarf.Offset {
	if len(fields) == 0 {
		return d.structHeader(dieLeaf, name, size)
	}
	start := d.structHeader(dieStruct, name, size)
	for _, f := range fields {
		d.member(f)
	}
	d.info = append(d.info, 0)
	return start
}

// rustc omits DW_AT_discr_value on the variant selected by all remaining values.
const defaultVariant = -1

type fixtureVariant struct {
	name  string
	value int
	typ   dwarf.Offset
}

func (d *fixtureDWARF) enum(name string, size, tag uint16, tagType dwarf.Offset, variants ...fixtureVariant) dwarf.Offset {
	start := d.structHeader(dieStruct, name, size)
	d.entry(diePart)
	d.ref(dwarf.Offset(len(d.info) + 4)) // DW_AT_discr refers to the member following its ref4.
	d.member(fixtureMember{"", tag, tagType})
	for _, v := range variants {
		if v.value == defaultVariant {
			d.entry(dieDefaultVariant)
		} else {
			d.info = append(d.info, dieVariant, byte(v.value))
		}
		d.member(fixtureMember{v.name, 0, v.typ})
		d.info = append(d.info, 0)
	}
	d.info = append(d.info, 0, 0)
	return start
}

func (d *fixtureDWARF) option(name string, size, tag uint16, tagType dwarf.Offset, payloadOffset uint16, payload dwarf.Offset, noneValue, someValue int) dwarf.Offset {
	none := d.structure("None", size)
	some := d.structure("Some", size, fixtureMember{"__0", payloadOffset, payload})
	return d.enum(name, size, tag, tagType, fixtureVariant{"None", noneValue, none}, fixtureVariant{"Some", someValue, some})
}
