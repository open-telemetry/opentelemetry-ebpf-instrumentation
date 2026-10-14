// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestTraceAttributesSelector_HTTPClientServerAddressHasNoPort(t *testing.T) {
	tests := []struct {
		hostHeader  string
		wantAddress string
		wantURL     string
	}{
		{hostHeader: "example.com", wantAddress: "example.com", wantURL: "http://example.com/users/42"},
		{hostHeader: "example.com:8080", wantAddress: "example.com", wantURL: "http://example.com:8080/users/42"},
		{hostHeader: "10.0.0.5:8080", wantAddress: "10.0.0.5", wantURL: "http://10.0.0.5:8080/users/42"},
		{hostHeader: "[2001:db8::1]:8080", wantAddress: "2001:db8::1", wantURL: "http://[2001:db8::1]:8080/users/42"},
	}
	for _, tc := range tests {
		t.Run(tc.hostHeader, func(t *testing.T) {
			span := httpClientSpan(request.HTTPSubtypeNone, "")
			span.Statement = "http" + request.SchemeHostSeparator + tc.hostHeader
			attrs := TraceAttributesSelector(span, defaultTraceAttrs(t))

			address, ok := attrValue(attrs, "server.address")
			require.True(t, ok)
			assert.Equal(t, tc.wantAddress, address.AsString())

			url, ok := attrValue(attrs, "url.full")
			require.True(t, ok)
			assert.Equal(t, tc.wantURL, url.AsString())
		})
	}
}
