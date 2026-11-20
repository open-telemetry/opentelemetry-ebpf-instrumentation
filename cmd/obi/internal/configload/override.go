// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configload // import "go.opentelemetry.io/obi/cmd/obi/internal/configload"

import "reflect"

// override sets in dst every value of layer that differs from defaults, the configuration that
// the layer's version produces without settings. Structs whose fields are all exported are
// merged field by field; any other value, including slices and maps, replaces the dst value as a
// whole. It never writes into memory that dst shares with other configurations.
func override(dst, layer, defaults reflect.Value) {
	switch {
	case dst.Kind() == reflect.Func:
		overrideFunc(dst, layer, defaults)
	case isMergeableStruct(dst.Type()):
		for i := range dst.NumField() {
			override(dst.Field(i), layer.Field(i), defaults.Field(i))
		}
	case reflect.DeepEqual(layer.Interface(), defaults.Interface()):
		return
	case isMergeableStructPointer(dst, layer, defaults):
		clone := reflect.New(dst.Type().Elem())
		clone.Elem().Set(dst.Elem())
		dst.Set(clone)
		override(clone.Elem(), layer.Elem(), defaults.Elem())
	default:
		dst.Set(layer)
	}
}

// overrideFunc copies the functions that a layer defines when its defaults do not.
// Functions are not comparable, so a layer cannot replace a default function.
func overrideFunc(dst, layer, defaults reflect.Value) {
	if !layer.IsNil() && defaults.IsNil() {
		dst.Set(layer)
	}
}

func isMergeableStruct(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	for field := range t.Fields() {
		if !field.IsExported() {
			return false
		}
	}
	return true
}

func isMergeableStructPointer(values ...reflect.Value) bool {
	for _, value := range values {
		if value.Kind() != reflect.Pointer || value.IsNil() || !isMergeableStruct(value.Type().Elem()) {
			return false
		}
	}
	return true
}
