// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// StatGetters returns the attributes.Getter function that returns the string value of a given
// attribute name.
//
//nolint:cyclop
func StatGetters(name attr.Name) (attributes.Getter[*Stat, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Stat, attribute.KeyValue]
	switch name {
	case attr.OBIIP:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.OBIIP), s.Attrs.OBIIP) }
	case attr.SrcAddress:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.String(string(attr.SrcAddress), s.Attrs.SourceAddress)
		}
	case attr.DstAddress:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.String(string(attr.DstAddress), s.Attrs.DestinationAddress)
		}
	case attr.SrcPort:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.Int(string(attr.SrcPort), s.Attrs.SourcePort)
		}
	case attr.DstPort:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.Int(string(attr.DstPort), s.Attrs.DestinationPort)
		}
	case attr.SrcName:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.SrcName), s.Attrs.SrcName) }
	case attr.DstName:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.DstName), s.Attrs.DstName) }
	case attr.SrcZone:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.SrcZone), s.Attrs.SrcZone) }
	case attr.DstZone:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.DstZone), s.Attrs.DstZone) }
	default:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(name), s.Attrs.Metadata[name]) }
	}
	return getter, getter != nil
}

func StatStringGetters(name attr.Name) (attributes.Getter[*Stat, string], bool) {
	if g, ok := StatGetters(name); ok {
		return func(s *Stat) string { return g(s).Value.Emit() }, true
	}
	return nil, false
}
