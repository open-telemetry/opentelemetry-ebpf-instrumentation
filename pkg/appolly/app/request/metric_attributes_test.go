// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
