// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestRenameUnresolved_OTEL_ServerSide(t *testing.T) {
	tests := []struct {
		name               string
		input              Span
		expectedClient     string
		expectedClientAddr string
		expectedServer     string
		expectedServerAddr string
		rename             string
	}{
		{
			name: "rename disabled - all spans pass through unchanged",
			input: Span{
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:     "192.168.1.2",
			expectedClientAddr: "192.168.1.2",
			expectedServer:     "192.168.1.1",
			expectedServerAddr: "192.168.1.1",
			rename:             "",
		},
		{
			name: "renaming enabled - IPs are renamed out",
			input: Span{
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "192.168.1.2", // it takes the peer name instead of the raw "peer" attribute
			expectedServer:     "unknown",
			expectedServerAddr: "192.168.1.1",
			rename:             "unknown",
		},
		{
			name: "renaming enabled - hostnames are empty",
			input: Span{
				Type:      EventTypeHTTP,
				HostName:  "",
				Host:      "192.168.1.1",
				PeerName:  "",
				Peer:      "10.0.0.1",
				Statement: "http;frontend:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "10.0.0.1",
			expectedServer:     "unknown",
			expectedServerAddr: "192.168.1.1",
			rename:             "unknown",
		},
		{
			name: "IPv6 addresses should be renamed too",
			input: Span{
				Type:      EventTypeHTTP,
				HostName:  "2001:db8::1",
				Host:      "::1",
				PeerName:  "2001:db8::2",
				Peer:      "::2",
				Statement: "http;[2001:db8::3]:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "2001:db8::2",
			expectedServer:     "unknown",
			expectedServerAddr: "2001:db8::1",
			rename:             "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the attributes getter
			getter := SpanOTELGetters(tt.rename)

			assert.Equal(t, tt.expectedClient, getVal(t, getter, &tt.input, attr.Client).Value.AsString())
			assert.Equal(t, tt.expectedClientAddr, getVal(t, getter, &tt.input, attr.ClientAddr).Value.AsString())
			assert.Equal(t, tt.expectedServer, getVal(t, getter, &tt.input, attr.Server).Value.AsString())
			assert.Equal(t, tt.expectedServerAddr, getVal(t, getter, &tt.input, attr.ServerAddr).Value.AsString())
		})
	}
}

func TestRenameUnresolved_OTEL_ClientSide(t *testing.T) {
	tests := []struct {
		name               string
		input              Span
		expectedClient     string
		expectedClientAddr string
		expectedServer     string
		expectedServerAddr string
		rename             string
	}{
		{
			name: "rename disabled - all spans pass through unchanged",
			input: Span{
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:     "192.168.1.2",
			expectedClientAddr: "192.168.1.2",
			expectedServer:     "192.168.1.1",
			expectedServerAddr: "192.168.1.3:8080", // serverAddr is now taken from statement
			rename:             "",
		},
		{
			name: "renaming enabled - IPs are renamed out",
			input: Span{
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "192.168.1.2", // it takes the peer name instead of the raw "peer" attribute
			expectedServer:     "unknown",
			expectedServerAddr: "192.168.1.3:8080",
			rename:             "unknown",
		},
		{
			name: "renaming enabled - hostnames are empty",
			input: Span{
				Type:      EventTypeHTTPClient,
				HostName:  "",
				Host:      "192.168.1.1",
				PeerName:  "",
				Peer:      "10.0.0.1",
				Statement: "http;frontend:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "10.0.0.1",
			expectedServer:     "unknown",
			expectedServerAddr: "frontend:8080",
			rename:             "unknown",
		},
		{
			name: "IPv6 addresses should be renamed too",
			input: Span{
				Type:      EventTypeHTTPClient,
				HostName:  "2001:db8::1",
				Host:      "::1",
				PeerName:  "2001:db8::2",
				Peer:      "::2",
				Statement: "http;[2001:db8::3]:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "2001:db8::2",
			expectedServer:     "unknown",
			expectedServerAddr: "[2001:db8::3]:8080",
			rename:             "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the attributes getter
			getter := SpanOTELGetters(tt.rename)

			assert.Equal(t, tt.expectedClient, getVal(t, getter, &tt.input, attr.Client).Value.AsString())
			assert.Equal(t, tt.expectedClientAddr, getVal(t, getter, &tt.input, attr.ClientAddr).Value.AsString())
			assert.Equal(t, tt.expectedServer, getVal(t, getter, &tt.input, attr.Server).Value.AsString())
			assert.Equal(t, tt.expectedServerAddr, getVal(t, getter, &tt.input, attr.ServerAddr).Value.AsString())
		})
	}
}

func TestRenameUnresolved_Prom_ServerSide(t *testing.T) {
	tests := []struct {
		name               string
		input              Span
		expectedClient     string
		expectedClientAddr string
		expectedServer     string
		expectedServerAddr string
		rename             string
	}{
		{
			name: "rename disabled - all spans pass through unchanged",
			input: Span{
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:     "192.168.1.2",
			expectedClientAddr: "192.168.1.2",
			expectedServer:     "192.168.1.1",
			expectedServerAddr: "192.168.1.1",
			rename:             "",
		},
		{
			name: "renaming enabled - IPs are renamed out",
			input: Span{
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "192.168.1.2", // it takes the peer name instead of the raw "peer" attribute
			expectedServer:     "unknown",
			expectedServerAddr: "192.168.1.1",
			rename:             "unknown",
		},
		{
			name: "renaming enabled - hostnames are empty",
			input: Span{
				Type:      EventTypeHTTP,
				HostName:  "",
				Host:      "192.168.1.1",
				PeerName:  "",
				Peer:      "10.0.0.1",
				Statement: "http;frontend:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "10.0.0.1",
			expectedServer:     "unknown",
			expectedServerAddr: "192.168.1.1",
			rename:             "unknown",
		},
		{
			name: "IPv6 addresses should be renamed too",
			input: Span{
				Type:      EventTypeHTTP,
				HostName:  "2001:db8::1",
				Host:      "::1",
				PeerName:  "2001:db8::2",
				Peer:      "::2",
				Statement: "http;[2001:db8::3]:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "2001:db8::2",
			expectedServer:     "unknown",
			expectedServerAddr: "2001:db8::1",
			rename:             "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the attributes getter
			getter := SpanPromGetters(tt.rename)

			assert.Equal(t, tt.expectedClient, getVal(t, getter, &tt.input, attr.Client))
			assert.Equal(t, tt.expectedClientAddr, getVal(t, getter, &tt.input, attr.ClientAddr))
			assert.Equal(t, tt.expectedServer, getVal(t, getter, &tt.input, attr.Server))
			assert.Equal(t, tt.expectedServerAddr, getVal(t, getter, &tt.input, attr.ServerAddr))
		})
	}
}

func TestRenameUnresolved_Prom_ClientSide(t *testing.T) {
	tests := []struct {
		name               string
		input              Span
		expectedClient     string
		expectedClientAddr string
		expectedServer     string
		expectedServerAddr string
		rename             string
	}{
		{
			name: "rename disabled - all spans pass through unchanged",
			input: Span{
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:     "192.168.1.2",
			expectedClientAddr: "192.168.1.2",
			expectedServer:     "192.168.1.1",
			expectedServerAddr: "192.168.1.3:8080", // serverAddr is now taken from statement
			rename:             "",
		},
		{
			name: "renaming enabled - IPs are renamed out",
			input: Span{
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "192.168.1.2", // it takes the peer name instead of the raw "peer" attribute
			expectedServer:     "unknown",
			expectedServerAddr: "192.168.1.3:8080",
			rename:             "unknown",
		},
		{
			name: "renaming enabled - hostnames are empty",
			input: Span{
				Type:      EventTypeHTTPClient,
				HostName:  "",
				Host:      "192.168.1.1",
				PeerName:  "",
				Peer:      "10.0.0.1",
				Statement: "http;frontend:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "10.0.0.1",
			expectedServer:     "unknown",
			expectedServerAddr: "frontend:8080",
			rename:             "unknown",
		},
		{
			name: "IPv6 addresses should be renamed too",
			input: Span{
				Type:      EventTypeHTTPClient,
				HostName:  "2001:db8::1",
				Host:      "::1",
				PeerName:  "2001:db8::2",
				Peer:      "::2",
				Statement: "http;[2001:db8::3]:8080",
			},
			expectedClient:     "unknown",
			expectedClientAddr: "2001:db8::2",
			expectedServer:     "unknown",
			expectedServerAddr: "[2001:db8::3]:8080",
			rename:             "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the attributes getter
			getter := SpanPromGetters(tt.rename)

			assert.Equal(t, tt.expectedClient, getVal(t, getter, &tt.input, attr.Client))
			assert.Equal(t, tt.expectedClientAddr, getVal(t, getter, &tt.input, attr.ClientAddr))
			assert.Equal(t, tt.expectedServer, getVal(t, getter, &tt.input, attr.Server))
			assert.Equal(t, tt.expectedServerAddr, getVal(t, getter, &tt.input, attr.ServerAddr))
		})
	}
}

func getVal[O any](t *testing.T, getters attributes.NamedGetters[*Span, O], span *Span, name attr.Name) O {
	t.Helper()
	getter, ok := getters(name)
	require.Truef(t, ok, "getter %s should be found", name)
	return getter(span)
}
