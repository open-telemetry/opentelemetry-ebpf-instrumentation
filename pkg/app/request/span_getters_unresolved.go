// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"net"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func unresolvedValue(value, replacement string) string {
	if replacement != "" {
		if net.ParseIP(value) != nil {
			return replacement
		}
	}

	return value
}

// otelUnresolvedHostGetters wraps spanOTELGetters but replacing client and server address
// unresolved metrics by a user-provided tag (usually "unresolved")
func otelUnresolvedHostGetters(unresolved UnresolvedNames) func(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
	return func(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
		getter, ok := spanOTELGetters(name)
		if name == attr.Client {
			return func(s *Span) attribute.KeyValue {
				kv := getter(s)
				if s.IsClientSpan() {
					kv.Value = attribute.StringValue(unresolvedValue(kv.Value.AsString(), unresolved.Generic))
				} else {
					kv.Value = attribute.StringValue(unresolvedValue(kv.Value.AsString(), unresolved.Incoming))
				}
				return kv
			}, true
		} else if name == attr.Server {
			return func(s *Span) attribute.KeyValue {
				kv := getter(s)
				if s.IsClientSpan() {
					kv.Value = attribute.StringValue(unresolvedValue(kv.Value.AsString(), unresolved.Outgoing))
				} else {
					kv.Value = attribute.StringValue(unresolvedValue(kv.Value.AsString(), unresolved.Generic))
				}
				return kv
			}, true
		}

		return getter, ok
	}
}

// promUnresolvedHostGetters wraps spanPromGetters but replacing client and server address
// unresolved metrics by a user-provided tag (usually "unresolved")
func promUnresolvedHostGetters(unresolved UnresolvedNames) func(name attr.Name) (attributes.Getter[*Span, string], bool) {
	return func(name attr.Name) (attributes.Getter[*Span, string], bool) {
		getter, ok := spanPromGetters(name)
		if name == attr.Client {
			return func(span *Span) string {
				val := getter(span)
				if span.IsClientSpan() {
					return unresolvedValue(val, unresolved.Generic)
				}
				return unresolvedValue(val, unresolved.Incoming)
			}, true
		} else if name == attr.Server {
			return func(span *Span) string {
				val := getter(span)
				if span.IsClientSpan() {
					return unresolvedValue(val, unresolved.Outgoing)
				}
				return unresolvedValue(val, unresolved.Generic)
			}, true
		}
		return getter, ok
	}
}
