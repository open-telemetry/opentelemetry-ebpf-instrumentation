// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// dwarf.go extracts private Rust field, enum, protocol, and channel layouts
// from OBI's DWARF-enabled fixtures during offset generation.

package rustabi // import "go.opentelemetry.io/obi/internal/rustabi"

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"strings"

	"go.opentelemetry.io/obi/internal/dwarfutil"
)

const maxRustFieldOffset = 1 << 20

// typeOffset finds the DWARF entry for a decoded type even when several types share its name.
func (d *rustDwarfTypes) typeOffset(t dwarf.Type) (dwarf.Offset, error) {
	name := t.Common().Name
	if s, ok := t.(*dwarf.StructType); ok {
		name = s.StructName
	}

	for _, offset := range d.names[name] {
		candidate, err := d.data.Type(offset)
		if err == nil && candidate == t {
			return offset, nil
		}
	}

	return 0, fmt.Errorf("rust DWARF offset missing for %s", t)
}

// variant returns the payload type and byte offset of a named Rust enum variant.
func (d *rustDwarfTypes) variant(offset dwarf.Offset, name string) (uint32, dwarf.Type, error) {
	r := d.data.Reader()
	r.Seek(offset)
	depth := 0

	for {
		e, err := r.Next()
		if err != nil || e == nil {
			break
		}

		if e.Tag == 0 {
			depth--
			if depth == 0 {
				break
			}
			continue
		}

		if e.Tag == dwarf.TagMember && e.Val(dwarf.AttrName) == name {
			off, ok := e.Val(dwarf.AttrType).(dwarf.Offset)
			if !ok {
				return 0, nil, errors.New("rust variant type is missing")
			}

			base, ok := e.Val(dwarf.AttrDataMemberLoc).(int64)
			if !ok || base < 0 || base > maxRustFieldOffset {
				return 0, nil, errors.New("rust variant offset is invalid")
			}

			t, err := d.data.Type(off)
			return uint32(base), t, err
		}

		if e.Children {
			depth++
		}
	}

	return 0, nil, fmt.Errorf("rust variant %s is missing", name)
}

// path follows struct fields and enum variants to find the final type and its byte offset from the root.
func (d *rustDwarfTypes) path(t dwarf.Type, path ...string) (uint32, dwarf.Type, error) {
	var total uint32

	for _, name := range path {
		offset, field, err := rustDwarfField(t, name)
		if err != nil {
			typeOffset, err := d.typeOffset(t)
			if err != nil {
				return 0, nil, err
			}
			offset, field, err = d.variant(typeOffset, name)
			if err != nil {
				return 0, nil, err
			}
		}

		total += offset
		t = field
	}

	return total, t, nil
}

// discriminant locates the eight-byte tag that identifies the active enum variant.
func (d *rustDwarfTypes) discriminant(t dwarf.Type) (uint32, error) {
	offset, err := d.typeOffset(t)
	if err != nil {
		return 0, err
	}

	r := d.data.Reader()
	r.Seek(offset)
	parent, err := r.Next()
	if err != nil {
		return 0, err
	}
	if parent == nil || !parent.Children {
		return 0, errors.New("rust type has no variant part")
	}

	for {
		e, err := r.Next()
		if err != nil {
			return 0, err
		}
		if e == nil || e.Tag == 0 {
			break
		}

		if e.Tag != dwarf.TagVariantPart {
			r.SkipChildren()
			continue
		}

		discr, ok := e.Val(dwarf.AttrDiscr).(dwarf.Offset)
		if !ok {
			break
		}

		r.Seek(discr)

		member, err := r.Next()
		if err != nil || member == nil {
			break
		}

		typeOffset, ok := member.Val(dwarf.AttrType).(dwarf.Offset)
		if !ok {
			break
		}

		discrType, err := d.data.Type(typeOffset)
		if err != nil || discrType.Size() != 8 {
			break
		}

		base, ok := member.Val(dwarf.AttrDataMemberLoc).(int64)
		if !ok || base < 0 || base > maxRustFieldOffset {
			break
		}

		return uint32(base), nil
	}

	return 0, errors.New("rust message discriminant must be a validated u64")
}

// callback locates the variant tag, optional sender tag, and sender pointer shared by the Retry and NoRetry variants.
func (d *rustDwarfTypes) callback(t dwarf.Type, path ...string) (uint32, uint32, uint32, error) {
	base, callback, err := d.path(t, path...)
	if err != nil {
		return 0, 0, 0, err
	}

	tag, err := d.discriminant(callback)
	if err != nil {
		return 0, 0, 0, err
	}

	option, sender, err := d.path(callback, "Retry", "__0")
	if err != nil {
		return 0, 0, 0, err
	}

	some, err := d.discriminant(sender)

	pointerPath := []string{"inner", "Some", "__0", "ptr", "pointer"}
	if err == nil {
		some += base + option
		pointerPath = append([]string{"Some", "__0"}, pointerPath...)
	} else {
		some = 0
	}

	pointer, ptrType, err := d.path(sender, pointerPath...)
	if err != nil || ptrType.Size() != 8 {
		return 0, 0, 0, errors.New("rust oneshot pointer is not validated")
	}

	other, _, err := d.path(callback, append([]string{"NoRetry", "__0"}, pointerPath...)...)
	if err != nil || other != option+pointer {
		return 0, 0, 0, errors.New("rust callback variants have different pointer locations")
	}

	return base + tag, some, base + option + pointer, nil
}

// messageLayouts measures the Tokio queue slots, callback fields, and request headers for each supported Hyper envelope type.
func (d *rustDwarfTypes) messageLayouts() (map[string]MessageLayout, error) {
	channels := map[string]MessageLayout{}
	for name, offset := range d.types {
		if !strings.HasPrefix(name, "hyper::client::dispatch::Envelope<") {
			continue
		}

		t, err := d.data.Type(offset)
		if err != nil {
			return nil, err
		}

		var layout MessageLayout
		rx, err := d.data.Type(d.types["tokio::sync::mpsc::list::Rx<"+name+">"])
		if err != nil {
			return nil, err
		}

		layout.ListHead, _, err = rustDwarfField(rx, "head")
		if err != nil {
			return nil, err
		}

		layout.ListIndex, _, err = rustDwarfField(rx, "index")
		if err != nil {
			return nil, err
		}

		block, err := d.data.Type(d.types["tokio::sync::mpsc::block::Block<"+name+">"])
		if err != nil {
			return nil, err
		}

		_, values, err := rustDwarfField(block, "values", "__0")
		if err != nil {
			return nil, err
		}

		array, ok := values.(*dwarf.ArrayType)
		if !ok || array.Count != 32 {
			return nil, errors.New("rust channel block capacity is not validated")
		}

		layout.SlotMask = uint32(array.Count - 1)
		layout.TxTag, layout.TxSome, layout.TxPointer, err = d.callback(t, "__0", "Some", "__0", "__1")
		if err != nil {
			return nil, err
		}

		poll, ok := d.types["core::task::poll::Poll<core::option::Option<"+name+">>"]
		if !ok {
			continue
		}

		t, err = d.data.Type(poll)
		if err != nil {
			return nil, err
		}

		layout.RxTag, layout.RxSome, layout.RxPointer, err = d.callback(t, "Ready", "__0", "Some", "__0", "__0", "Some", "__0", "__1")
		if err != nil {
			return nil, err
		}

		discr, err := d.discriminant(t)
		if err != nil || discr != layout.RxTag {
			return nil, errors.New("rust receive result uses a different message discriminant")
		}

		layout.RxHeaders, _, err = d.path(t, "Ready", "__0", "Some", "__0", "__0", "Some", "__0", "__0", "head", "headers")
		if err != nil {
			return nil, err
		}

		layout.Request = true
		channels[name] = layout
	}

	return channels, nil
}

type rustDwarfTypes struct {
	data  *dwarf.Data
	types map[string]dwarf.Offset
	names map[string][]dwarf.Offset
}

// readRustDwarfTypes indexes the fixture's struct definitions by qualified and short name in one DWARF scan.
func readRustDwarfTypes(f *elf.File) (*rustDwarfTypes, error) {
	d, err := f.DWARF()
	if err != nil {
		return nil, err
	}

	index := &rustDwarfTypes{data: d, types: map[string]dwarf.Offset{}, names: map[string][]dwarf.Offset{}}
	reader := d.Reader()
	var scopes []string
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			return index, err
		}

		if entry.Tag == 0 {
			if len(scopes) > 0 {
				scopes = scopes[:len(scopes)-1]
			}
			continue
		}

		name, _ := entry.Val(dwarf.AttrName).(string)
		if entry.Tag == dwarf.TagStructType && entry.Val(dwarf.AttrDeclaration) != true {
			var parts []string

			for _, scope := range scopes {
				if scope != "" {
					parts = append(parts, scope)
				}
			}

			parts = append(parts, name)
			index.types[strings.Join(parts, "::")] = entry.Offset
			index.names[name] = append(index.names[name], entry.Offset)
		}

		if entry.Children {
			scope := ""
			if entry.Tag == dwarf.TagNamespace {
				scope = name
			}
			scopes = append(scopes, scope)
		}
	}
}

// rustDwarfField returns a nested struct field's type and byte offset, rejecting offsets above the Rust limit.
func rustDwarfField(t dwarf.Type, path ...string) (uint32, dwarf.Type, error) {
	offset, leaf, err := dwarfutil.FieldPath(t, path...)
	if err != nil {
		return 0, nil, err
	}
	if offset > maxRustFieldOffset {
		return 0, nil, fmt.Errorf("rust field %s offset %d exceeds %d", strings.Join(path, "."), offset, maxRustFieldOffset)
	}
	return uint32(offset), leaf, nil
}

// field looks up a struct by its qualified Rust name and returns the byte offset of a nested field.
func (d *rustDwarfTypes) field(name string, size int64, path ...string) (uint32, error) {
	offset, ok := d.types[name]
	if !ok {
		return 0, fmt.Errorf("rust DWARF type %s is missing", name)
	}

	t, err := d.data.Type(offset)
	if err != nil {
		return 0, err
	}

	return rustFieldOffset(t, size, path...)
}

// rustFieldOffset returns a nested field's byte offset and checks its size when a nonzero size is supplied.
func rustFieldOffset(t dwarf.Type, size int64, path ...string) (uint32, error) {
	field, leaf, err := rustDwarfField(t, path...)
	if err == nil && size != 0 && leaf.Size() != size {
		return 0, fmt.Errorf("rust field %s has size %d, expected %d", strings.Join(path, "."), leaf.Size(), size)
	}

	return field, err
}

// customHeaderName locates the byte pointer and length of a custom HTTP header name.
func (d *rustDwarfTypes) customHeaderName() (uint32, uint32, error) {
	offset, ok := d.types["http::header::name::Repr<http::header::name::Custom>"]
	if !ok {
		return 0, 0, errors.New("rust HeaderName variant metadata is missing")
	}

	base, custom, err := d.variant(offset, "Custom")
	if err != nil {
		return 0, 0, err
	}
	ptr, err := rustFieldOffset(custom, 8, "__0", "__0", "bytes", "ptr")
	if err != nil {
		return 0, 0, err
	}
	length, err := rustFieldOffset(custom, 8, "__0", "__0", "bytes", "len")
	if err != nil {
		return 0, 0, err
	}
	return base + ptr, base + length, nil
}

// protocolLayouts measures the Rust vector and HTTP request layouts used by the HTTP/1 probes.
func (d *rustDwarfTypes) protocolLayouts() (Layouts, error) {
	var config Layouts
	const vec = "alloc::vec::Vec<u8, alloc::alloc::Global>"
	fields := []struct {
		dst      *uint32
		typeName string
		path     []string
	}{
		{&config.VecPtr, vec, []string{"buf", "inner", "ptr", "pointer"}},
		{&config.VecLen, vec, []string{"len"}},
		{&config.VecCap, vec, []string{"buf", "inner", "cap", "__0"}},
		{&config.HeaderEntries, "http::header::map::HeaderMap<http::header::value::HeaderValue>", []string{"entries", "buf", "inner", "ptr", "pointer"}},
		{&config.HeaderCount, "http::header::map::HeaderMap<http::header::value::HeaderValue>", []string{"entries", "len"}},
		{&config.ValuePtr, "http::header::map::Bucket<http::header::value::HeaderValue>", []string{"value", "inner", "ptr"}},
		{&config.ValueLen, "http::header::map::Bucket<http::header::value::HeaderValue>", []string{"value", "inner", "len"}},
	}

	requestHeaders, err := d.field("http::request::Request<()>", 0, "head", "headers")
	if err != nil {
		return config, err
	}

	config.RequestHeaders = requestHeaders
	config.HTTP1 = 1
	for _, field := range fields {
		*field.dst, err = d.field(field.typeName, 8, field.path...)
		if err != nil {
			return config, err
		}
	}

	const bucket = "http::header::map::Bucket<http::header::value::HeaderValue>"
	bucketType, err := d.data.Type(d.types[bucket])
	if err != nil {
		config.HTTP1 = 0
		return config, nil
	}

	config.BucketSize = uint32(bucketType.Size())

	nameBase, err := d.field(bucket, 0, "key", "inner")
	if err != nil {
		config.HTTP1 = 0
		return config, nil
	}

	ptr, length, err := d.customHeaderName()
	if err != nil {
		config.HTTP1 = 0
		return config, nil
	}

	config.NamePtr = nameBase + ptr
	config.NameLen = nameBase + length
	return config, nil
}
