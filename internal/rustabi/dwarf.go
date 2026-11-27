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
	"reflect"
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
	parent, err := r.Next()
	if err != nil {
		return 0, nil, err
	}
	if parent == nil || !parent.Children {
		return 0, nil, fmt.Errorf("rust variant %s is missing", name)
	}

	// Rust stores each variant as enum -> variant part -> variant -> member.
	variantTags := [...]dwarf.Tag{dwarf.TagVariantPart, dwarf.TagVariant, dwarf.TagMember}
	for depth := 1; depth > 0; {
		e, err := r.Next()
		if err != nil {
			return 0, nil, err
		}
		if e == nil {
			break
		}

		if e.Tag == 0 {
			depth--
			continue
		}

		if e.Tag != variantTags[depth-1] {
			r.SkipChildren()
			continue
		}

		if depth == len(variantTags) && e.Val(dwarf.AttrName) == name {
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

		if depth == len(variantTags) {
			r.SkipChildren()
			continue
		}

		if e.Children {
			depth++
		}
	}

	return 0, nil, fmt.Errorf("rust variant %s is missing", name)
}

// path follows struct fields and enum variants to find the final type and its byte offset from the starting type.
func (d *rustDwarfTypes) path(t dwarf.Type, path ...string) (uint32, dwarf.Type, error) {
	var total uint32

	for _, name := range path {
		offset, field, err := rustDwarfField(t, name)
		if errors.Is(err, dwarfutil.ErrFieldNotFound) {
			typeOffset, lookupErr := d.typeOffset(t)
			if lookupErr != nil {
				return 0, nil, lookupErr
			}
			offset, field, err = d.variant(typeOffset, name)
		}
		if err != nil {
			return 0, nil, err
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

	retrySome, retryPointer, err := d.callbackSender(callback, base, "Retry")
	if err != nil {
		return 0, 0, 0, err
	}
	noRetrySome, noRetryPointer, err := d.callbackSender(callback, base, "NoRetry")
	if err != nil {
		return 0, 0, 0, err
	}
	if retrySome != noRetrySome || retryPointer != noRetryPointer {
		return 0, 0, 0, errors.New("rust callback variants have different sender layouts")
	}

	return base + tag, retrySome, retryPointer, nil
}

// Both callback variants use one BPF layout. A plain sender has no outer Some tag.
func (d *rustDwarfTypes) callbackSender(callback dwarf.Type, base uint32, variant string) (uint32, uint32, error) {
	offset, sender, err := d.path(callback, variant, "__0")
	if err != nil {
		return 0, 0, fmt.Errorf("rust callback %s sender: %w", variant, err)
	}
	base += offset

	var some uint32
	if tag, err := d.discriminant(sender); err == nil {
		some = base + tag
		offset, sender, err = d.path(sender, "Some", "__0")
		if err != nil {
			return 0, 0, fmt.Errorf("rust callback %s option: %w", variant, err)
		}
		base += offset
	}

	offset, ptrType, err := d.path(sender, "inner", "Some", "__0", "ptr", "pointer")
	if err != nil {
		return 0, 0, fmt.Errorf("rust callback %s oneshot pointer: %w", variant, err)
	}
	if ptrType.Size() != 8 {
		return 0, 0, fmt.Errorf("rust callback %s oneshot pointer is not validated", variant)
	}
	return some, base + offset, nil
}

// messageLayouts measures the Tokio queue slots, callback fields, and request headers for each supported Hyper envelope type.
func (r *layoutReader) messageLayouts(requestHeaders uint32) (map[string]MessageLayout, error) {
	channels := map[string]MessageLayout{}
	for name := range r.typeEntryOffsets {
		if !strings.HasPrefix(name, "hyper::client::dispatch::Envelope<") {
			continue
		}

		poll := "core::task::poll::Poll<core::option::Option<" + name + ">>"
		if len(r.typeEntryOffsets[poll]) == 0 {
			continue
		}

		var layout MessageLayout
		for _, measurement := range []struct {
			name string
			read func(dwarf.Type, *MessageLayout) error
		}{
			{"tokio::sync::mpsc::list::Rx<" + name + ">", listOffsets},
			{"tokio::sync::mpsc::block::Block<" + name + ">", blockOffsets},
			{name, func(t dwarf.Type, layout *MessageLayout) error {
				return r.sendOffsets(t, layout, requestHeaders)
			}},
			{poll, r.receiveOffsets},
		} {
			if err := measureType(r, measurement.name, &layout, measurement.read); err != nil {
				return nil, err
			}
		}

		channels[name] = layout
	}

	return channels, nil
}

func listOffsets(t dwarf.Type, layout *MessageLayout) error {
	var err error
	layout.ListHead, _, err = rustDwarfField(t, "head")
	if err != nil {
		return err
	}

	layout.ListIndex, _, err = rustDwarfField(t, "index")
	return err
}

func blockOffsets(t dwarf.Type, layout *MessageLayout) error {
	_, values, err := rustDwarfField(t, "values", "__0")
	if err != nil {
		return err
	}

	array, ok := values.(*dwarf.ArrayType)
	if !ok || array.Count != 32 {
		return errors.New("rust channel block capacity is not validated")
	}

	layout.SlotMask = uint32(array.Count - 1)
	return nil
}

func (r *layoutReader) sendOffsets(t dwarf.Type, layout *MessageLayout, requestHeaders uint32) error {
	var err error
	layout.TxTag, layout.TxSome, layout.TxPointer, err = r.callback(t, "__0", "Some", "__0", "__1")
	if err != nil {
		return err
	}

	_, requestType, err := r.path(t, "__0", "Some", "__0", "__0")
	if err != nil {
		return err
	}

	headers, err := rustFieldOffset(requestType, 0, "head", "headers")
	if err != nil {
		return err
	}

	// Body alignment can move Request.head. This fallback uses one shared offset.
	layout.Request = headers == requestHeaders

	return nil
}

func (r *layoutReader) receiveOffsets(t dwarf.Type, layout *MessageLayout) error {
	var err error
	layout.RxTag, layout.RxSome, layout.RxPointer, err = r.callback(t, "Ready", "__0", "Some", "__0", "__0", "Some", "__0", "__1")
	if err != nil {
		return err
	}

	discr, err := r.discriminant(t)
	if err != nil || discr != layout.RxTag {
		return errors.New("rust receive result uses a different message discriminant")
	}

	layout.RxHeaders, _, err = r.path(t, "Ready", "__0", "Some", "__0", "__0", "Some", "__0", "__0", "head", "headers")

	return err
}

// The layout reader uses the qualified type names to find every linked definition.
// Nested fields and enum variants follow the type references within each definition.
type layoutReader struct {
	rustDwarfTypes
	typeEntryOffsets map[string][]dwarf.Offset
}

type rustDwarfTypes struct {
	data  *dwarf.Data
	names map[string][]dwarf.Offset
}

// Cargo can link several crate versions with the same qualified type name.
// Measure just this type's fields in each definition before adding them to the layout.
func measureType[T Layouts | MessageLayout](r *layoutReader, name string, layout *T, read func(dwarf.Type, *T) error) error {
	offsets := r.typeEntryOffsets[name]
	if len(offsets) == 0 {
		return fmt.Errorf("rust DWARF type %s is missing", name)
	}

	var first T
	for i, offset := range offsets {
		t, err := r.data.Type(offset)
		if err != nil {
			return err
		}

		measured := *layout
		if err := read(t, &measured); err != nil {
			return err
		}

		if i == 0 {
			first = measured
		} else if measured != first {
			return reportConflictingOffsets(name, first, measured)
		}
	}

	*layout = first
	return nil
}

func reportConflictingOffsets[T Layouts | MessageLayout](name string, first, other T) error {
	a, b := reflect.ValueOf(first), reflect.ValueOf(other)
	for i := range a.NumField() {
		x, y := a.Field(i).Interface(), b.Field(i).Interface()
		if x != y {
			return fmt.Errorf("conflicting %s %s: %v and %v", name, a.Type().Field(i).Name, x, y)
		}
	}

	return fmt.Errorf("conflicting layouts for %s", name)
}

// newLayoutReader indexes the fixture's struct definitions by qualified and short name in one DWARF scan.
func newLayoutReader(f *elf.File) (*layoutReader, error) {
	d, err := f.DWARF()
	if err != nil {
		return nil, err
	}

	index := &layoutReader{
		rustDwarfTypes:   rustDwarfTypes{data: d, names: map[string][]dwarf.Offset{}},
		typeEntryOffsets: map[string][]dwarf.Offset{},
	}
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
			qualifiedName := strings.Join(parts, "::")
			index.typeEntryOffsets[qualifiedName] = append(index.typeEntryOffsets[qualifiedName], entry.Offset)
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

// rustFieldOffset returns a nested field's byte offset and checks its size when a nonzero size is supplied.
func rustFieldOffset(t dwarf.Type, size int64, path ...string) (uint32, error) {
	field, leaf, err := rustDwarfField(t, path...)
	if err == nil && size != 0 && leaf.Size() != size {
		return 0, fmt.Errorf("rust field %s has size %d, expected %d", strings.Join(path, "."), leaf.Size(), size)
	}

	return field, err
}

// customHeaderName locates the byte pointer and length of a custom HTTP header name.
func (d *rustDwarfTypes) customHeaderName(bucket dwarf.Type) (uint32, uint32, error) {
	base, custom, err := d.path(bucket, "key", "inner", "Custom")
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
func (r *layoutReader) protocolLayouts() (Layouts, error) {
	var layout Layouts
	for _, measurement := range []struct {
		name string
		read func(dwarf.Type, *Layouts) error
	}{
		{"http::request::Request<()>", requestOffsets},
		{"alloc::vec::Vec<u8, alloc::alloc::Global>", vecOffsets},
		{"http::header::map::HeaderMap<http::header::value::HeaderValue>", headerMapOffsets},
		{"http::header::map::Bucket<http::header::value::HeaderValue>", r.bucketOffsets},
	} {
		if err := measureType(r, measurement.name, &layout, measurement.read); err != nil {
			return Layouts{}, err
		}
	}

	layout.HTTP1 = 1
	return layout, nil
}

func requestOffsets(t dwarf.Type, layout *Layouts) error {
	var err error
	layout.RequestHeaders, err = rustFieldOffset(t, 0, "head", "headers")

	return err
}

func vecOffsets(t dwarf.Type, layout *Layouts) error {
	var err error
	layout.VecPtr, err = rustFieldOffset(t, 8, "buf", "inner", "ptr", "pointer")
	if err != nil {
		return err
	}

	layout.VecLen, err = rustFieldOffset(t, 8, "len")
	if err != nil {
		return err
	}
	layout.VecCap, err = rustFieldOffset(t, 8, "buf", "inner", "cap", "__0")

	return err
}

func headerMapOffsets(t dwarf.Type, layout *Layouts) error {
	var err error

	layout.HeaderEntries, err = rustFieldOffset(t, 8, "entries", "buf", "inner", "ptr", "pointer")
	if err != nil {
		return err
	}

	layout.HeaderCount, err = rustFieldOffset(t, 8, "entries", "len")

	return err
}

func (r *layoutReader) bucketOffsets(t dwarf.Type, layout *Layouts) error {
	layout.BucketSize = uint32(t.Size())
	var err error

	layout.ValuePtr, err = rustFieldOffset(t, 8, "value", "inner", "ptr")
	if err != nil {
		return err
	}

	layout.ValueLen, err = rustFieldOffset(t, 8, "value", "inner", "len")
	if err != nil {
		return err
	}

	layout.NamePtr, layout.NameLen, err = r.customHeaderName(t)

	return err
}
