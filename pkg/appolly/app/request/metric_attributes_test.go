// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestHostFromSchemeHost(t *testing.T) {
	t.Run("HTTP type with scheme and host", func(t *testing.T) {
		span := &Span{
			Type:      EventTypeHTTP,
			Statement: "http;example.com",
		}
		assert.Equal(t, "example.com", HostFromSchemeHost(span))
	})

	t.Run("HTTPClient type with scheme and host", func(t *testing.T) {
		span := &Span{
			Type:      EventTypeHTTPClient,
			Statement: "https;api.example.com",
		}
		assert.Equal(t, "api.example.com", HostFromSchemeHost(span))
	})

	t.Run("Statement with empty host after separator", func(t *testing.T) {
		span := &Span{
			Type:      EventTypeHTTP,
			Statement: "http;",
		}
		assert.Empty(t, HostFromSchemeHost(span))
	})

	t.Run("Statement without scheme-host separator", func(t *testing.T) {
		span := &Span{
			Type:      EventTypeHTTP,
			Statement: "http",
		}
		assert.Empty(t, HostFromSchemeHost(span))
	})

	t.Run("Non-HTTP event type", func(t *testing.T) {
		span := &Span{
			Type:      EventTypeSQLClient,
			Statement: "grpc;example.com",
		}
		assert.Empty(t, HostFromSchemeHost(span))
	})

	t.Run("Empty statement", func(t *testing.T) {
		span := &Span{
			Type:      EventTypeHTTP,
			Statement: "",
		}
		assert.Empty(t, HostFromSchemeHost(span))
	})
}

func TestJobAndInstanceAttributesUseOwnKeys(t *testing.T) {
	job := Job("checkout/api")
	assert.Equal(t, string(attr.Job), string(job.Key))
	assert.Equal(t, "checkout/api", job.Value.AsString())

	instance := Instance("pod-123")
	assert.Equal(t, string(attr.Instance), string(instance.Key))
	assert.Equal(t, "pod-123", instance.Value.AsString())
}

func TestHostWithoutPortFromSchemeHost(t *testing.T) {
	tests := []struct {
		statement string
		want      string
	}{
		{"http;example.com:8080", "example.com"},
		{"https;example.com", "example.com"},
		{"http;127.0.0.1:8080", "127.0.0.1"},
		{"http;127.0.0.1", "127.0.0.1"},
		{"http;[2001:db8::1]:8080", "2001:db8::1"},
		{"http;[2001:db8::1]", "2001:db8::1"},
		{"http;2001:db8::1", "2001:db8::1"},
		{"http;", ""},
		{"http", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.statement, func(t *testing.T) {
			span := &Span{Type: EventTypeHTTP, Statement: tt.statement}
			assert.Equal(t, tt.want, HostWithoutPort(HostFromSchemeHost(span)))
		})
	}
}
