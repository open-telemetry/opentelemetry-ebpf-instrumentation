// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestRenameUnresolved_OTEL_ServerSide(t *testing.T) {
	svc := svc.Attrs{
		UID: svc.UID{Name: "service", Namespace: "service-namespace"},
	}
	tests := []struct {
		name                    string
		input                   Span
		expectedClient          string
		expectedClientAddr      string
		expectedServer          string
		expectedServerAddr      string
		expectedServerNamespace string
		expectedClientNamespace string
		rename                  string
		renameOutgoing          string
		renameIncoming          string
	}{
		{
			name: "rename disabled - all spans pass through unchanged",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "192.168.1.2",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "192.168.1.1",
			expectedServerAddr:      "192.168.1.1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: "",
			rename:                  "",
			renameOutgoing:          "",
			renameIncoming:          "",
		},
		{
			name: "rename disabled for server - all server pass through unchanged",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "incoming",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "192.168.1.1",
			expectedServerAddr:      "192.168.1.1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "",
			renameOutgoing:          "",
			renameIncoming:          "incoming",
		},
		{
			name: "renaming enabled - IPs are renamed out",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "incoming",
			expectedClientAddr:      "192.168.1.2", // it takes the peer name instead of the raw "peer" attribute
			expectedServer:          "unknown",
			expectedServerAddr:      "192.168.1.1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
		{
			name: "renaming enabled - hostnames are empty",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "",
				Host:      "192.168.1.1",
				PeerName:  "",
				Peer:      "10.0.0.1",
				Statement: "http;frontend:8080",
			},
			expectedClient:          "incoming",
			expectedClientAddr:      "10.0.0.1",
			expectedServer:          "unknown",
			expectedServerAddr:      "192.168.1.1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
		{
			name: "IPv6 addresses should be renamed too",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "2001:db8::1",
				Host:      "::1",
				PeerName:  "2001:db8::2",
				Peer:      "::2",
				Statement: "http;[2001:db8::3]:8080",
			},
			expectedClient:          "incoming",
			expectedClientAddr:      "2001:db8::2",
			expectedServer:          "unknown",
			expectedServerAddr:      "2001:db8::1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := UnresolvedNames{
				Generic:  tt.rename,
				Outgoing: tt.renameOutgoing,
				Incoming: tt.renameIncoming,
			}
			// Create the attributes getter
			getter := SpanOTELGetters(cfg)

			assert.Equal(t, tt.expectedClient, getVal(t, getter, &tt.input, attr.Client).Value.AsString())
			assert.Equal(t, tt.expectedClientAddr, getVal(t, getter, &tt.input, attr.ClientAddr).Value.AsString())
			assert.Equal(t, tt.expectedServer, getVal(t, getter, &tt.input, attr.Server).Value.AsString())
			assert.Equal(t, tt.expectedServerAddr, getVal(t, getter, &tt.input, attr.ServerAddr).Value.AsString())
			assert.Equal(t, tt.expectedClientNamespace, getVal(t, getter, &tt.input, attr.ClientNamespace).Value.AsString())
			assert.Equal(t, tt.expectedServerNamespace, getVal(t, getter, &tt.input, attr.ServerNamespace).Value.AsString())
		})
	}
}

func TestRenameUnresolved_OTEL_ClientSide(t *testing.T) {
	svc := svc.Attrs{
		UID: svc.UID{Name: "service", Namespace: "service-namespace"},
	}
	tests := []struct {
		name                    string
		input                   Span
		expectedClient          string
		expectedClientAddr      string
		expectedServer          string
		expectedServerAddr      string
		expectedServerNamespace string
		expectedClientNamespace string
		rename                  string
		renameOutgoing          string
		renameIncoming          string
	}{
		{
			name: "rename disabled for generic - all server pass through unchanged, server exists",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "github.com",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;github.com:8080",
			},
			expectedClient:          "192.168.1.2",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "github.com",
			expectedServerAddr:      "github.com:8080", // serverAddr is now taken from statement
			expectedServerNamespace: "",
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "",
			renameOutgoing:          "outgoing",
			renameIncoming:          "",
		},
		{
			name: "rename disabled - all spans pass through unchanged",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "192.168.1.2",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "192.168.1.1",
			expectedServerAddr:      "192.168.1.3:8080", // serverAddr is now taken from statement
			expectedServerNamespace: "",
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "",
			renameOutgoing:          "",
			renameIncoming:          "",
		},
		{
			name: "rename disabled for generic - all server pass through unchanged",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "192.168.1.2",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "outgoing",
			expectedServerAddr:      "192.168.1.3:8080", // serverAddr is now taken from statement
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "",
			renameOutgoing:          "outgoing",
			renameIncoming:          "",
		},
		{
			name: "renaming enabled - IPs are renamed out",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "unknown",
			expectedClientAddr:      "192.168.1.2", // it takes the peer name instead of the raw "peer" attribute
			expectedServer:          "outgoing",
			expectedServerAddr:      "192.168.1.3:8080",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
		{
			name: "renaming enabled - hostnames are empty",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "",
				Host:      "192.168.1.1",
				PeerName:  "",
				Peer:      "10.0.0.1",
				Statement: "http;frontend:8080",
			},
			expectedClient:          "unknown",
			expectedClientAddr:      "10.0.0.1",
			expectedServer:          "outgoing",
			expectedServerAddr:      "frontend:8080",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
		{
			name: "IPv6 addresses should be renamed too",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "2001:db8::1",
				Host:      "::1",
				PeerName:  "2001:db8::2",
				Peer:      "::2",
				Statement: "http;[2001:db8::3]:8080",
			},
			expectedClient:          "unknown",
			expectedClientAddr:      "2001:db8::2",
			expectedServer:          "outgoing",
			expectedServerAddr:      "[2001:db8::3]:8080",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := UnresolvedNames{
				Generic:  tt.rename,
				Outgoing: tt.renameOutgoing,
				Incoming: tt.renameIncoming,
			}

			// Create the attributes getter
			getter := SpanOTELGetters(cfg)

			assert.Equal(t, tt.expectedClient, getVal(t, getter, &tt.input, attr.Client).Value.AsString())
			assert.Equal(t, tt.expectedClientAddr, getVal(t, getter, &tt.input, attr.ClientAddr).Value.AsString())
			assert.Equal(t, tt.expectedServer, getVal(t, getter, &tt.input, attr.Server).Value.AsString())
			assert.Equal(t, tt.expectedServerAddr, getVal(t, getter, &tt.input, attr.ServerAddr).Value.AsString())
			assert.Equal(t, tt.expectedClientNamespace, getVal(t, getter, &tt.input, attr.ClientNamespace).Value.AsString())
			assert.Equal(t, tt.expectedServerNamespace, getVal(t, getter, &tt.input, attr.ServerNamespace).Value.AsString())
		})
	}
}

func TestRenameUnresolved_Prom_ServerSide(t *testing.T) {
	svc := svc.Attrs{
		UID: svc.UID{Name: "service", Namespace: "service-namespace"},
	}
	tests := []struct {
		name                    string
		input                   Span
		expectedClient          string
		expectedClientAddr      string
		expectedServer          string
		expectedServerAddr      string
		expectedServerNamespace string
		expectedClientNamespace string
		rename                  string
		renameOutgoing          string
		renameIncoming          string
	}{
		{
			name: "rename disabled - all spans pass through unchanged",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "192.168.1.2",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "192.168.1.1",
			expectedServerAddr:      "192.168.1.1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: "",
			rename:                  "",
			renameOutgoing:          "",
			renameIncoming:          "",
		},
		{
			name: "rename disabled server - all server pass through unchanged",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "incoming1",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "192.168.1.1",
			expectedServerAddr:      "192.168.1.1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "",
			renameOutgoing:          "",
			renameIncoming:          "incoming1",
		},
		{
			name: "renaming enabled - IPs are renamed out",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "incoming",
			expectedClientAddr:      "192.168.1.2", // it takes the peer name instead of the raw "peer" attribute
			expectedServer:          "unknown",
			expectedServerAddr:      "192.168.1.1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
		{
			name: "renaming enabled - hostnames are empty",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "",
				Host:      "192.168.1.1",
				PeerName:  "",
				Peer:      "10.0.0.1",
				Statement: "http;frontend:8080",
			},
			expectedClient:          "incoming",
			expectedClientAddr:      "10.0.0.1",
			expectedServer:          "unknown",
			expectedServerAddr:      "192.168.1.1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
		{
			name: "IPv6 addresses should be renamed too",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTP,
				HostName:  "2001:db8::1",
				Host:      "::1",
				PeerName:  "2001:db8::2",
				Peer:      "::2",
				Statement: "http;[2001:db8::3]:8080",
			},
			expectedClient:          "incoming",
			expectedClientAddr:      "2001:db8::2",
			expectedServer:          "unknown",
			expectedServerAddr:      "2001:db8::1",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := UnresolvedNames{
				Generic:  tt.rename,
				Outgoing: tt.renameOutgoing,
				Incoming: tt.renameIncoming,
			}

			// Create the attributes getter
			getter := SpanPromGetters(cfg)

			assert.Equal(t, tt.expectedClient, getVal(t, getter, &tt.input, attr.Client))
			assert.Equal(t, tt.expectedClientAddr, getVal(t, getter, &tt.input, attr.ClientAddr))
			assert.Equal(t, tt.expectedServer, getVal(t, getter, &tt.input, attr.Server))
			assert.Equal(t, tt.expectedServerAddr, getVal(t, getter, &tt.input, attr.ServerAddr))
			assert.Equal(t, tt.expectedClientNamespace, getVal(t, getter, &tt.input, attr.ClientNamespace))
			assert.Equal(t, tt.expectedServerNamespace, getVal(t, getter, &tt.input, attr.ServerNamespace))
		})
	}
}

func TestRenameUnresolved_Prom_ClientSide(t *testing.T) {
	svc := svc.Attrs{
		UID: svc.UID{Name: "service", Namespace: "service-namespace"},
	}
	tests := []struct {
		name                    string
		input                   Span
		expectedClient          string
		expectedClientAddr      string
		expectedServer          string
		expectedServerAddr      string
		expectedServerNamespace string
		expectedClientNamespace string
		rename                  string
		renameOutgoing          string
		renameIncoming          string
	}{
		{
			name: "rename disabled - all spans pass through unchanged",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "192.168.1.2",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "192.168.1.1",
			expectedServerAddr:      "192.168.1.3:8080", // serverAddr is now taken from statement
			expectedServerNamespace: "",
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "",
			renameOutgoing:          "",
			renameIncoming:          "",
		},
		{
			name: "rename disabled client - all client pass through unchanged",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "192.168.1.2",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "outgoing2",
			expectedServerAddr:      "192.168.1.3:8080", // serverAddr is now taken from statement
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "",
			renameOutgoing:          "outgoing2",
			renameIncoming:          "",
		},
		{
			name: "rename disabled client - all client pass through unchanged, github",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "github.com",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;github.com:8080",
			},
			expectedClient:          "192.168.1.2",
			expectedClientAddr:      "192.168.1.2",
			expectedServer:          "github.com",
			expectedServerAddr:      "github.com:8080", // serverAddr is now taken from statement
			expectedServerNamespace: "",
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "",
			renameOutgoing:          "outgoing2",
			renameIncoming:          "",
		},
		{
			name: "renaming enabled - IPs are renamed out",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "192.168.1.1",
				Host:      "10.0.0.1",
				PeerName:  "192.168.1.2",
				Peer:      "10.0.0.2",
				Statement: "http;192.168.1.3:8080",
			},
			expectedClient:          "unknown",
			expectedClientAddr:      "192.168.1.2", // it takes the peer name instead of the raw "peer" attribute
			expectedServer:          "outgoing",
			expectedServerAddr:      "192.168.1.3:8080",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
		{
			name: "renaming enabled - hostnames are empty",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "",
				Host:      "192.168.1.1",
				PeerName:  "",
				Peer:      "10.0.0.1",
				Statement: "http;frontend:8080",
			},
			expectedClient:          "unknown",
			expectedClientAddr:      "10.0.0.1",
			expectedServer:          "outgoing",
			expectedServerAddr:      "frontend:8080",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
		{
			name: "IPv6 addresses should be renamed too",
			input: Span{
				Service:   svc,
				Type:      EventTypeHTTPClient,
				HostName:  "2001:db8::1",
				Host:      "::1",
				PeerName:  "2001:db8::2",
				Peer:      "::2",
				Statement: "http;[2001:db8::3]:8080",
			},
			expectedClient:          "unknown",
			expectedClientAddr:      "2001:db8::2",
			expectedServer:          "outgoing",
			expectedServerAddr:      "[2001:db8::3]:8080",
			expectedServerNamespace: svc.UID.Namespace,
			expectedClientNamespace: svc.UID.Namespace,
			rename:                  "unknown",
			renameOutgoing:          "outgoing",
			renameIncoming:          "incoming",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := UnresolvedNames{
				Generic:  tt.rename,
				Outgoing: tt.renameOutgoing,
				Incoming: tt.renameOutgoing,
			}

			// Create the attributes getter
			getter := SpanPromGetters(cfg)

			assert.Equal(t, tt.expectedClient, getVal(t, getter, &tt.input, attr.Client))
			assert.Equal(t, tt.expectedClientAddr, getVal(t, getter, &tt.input, attr.ClientAddr))
			assert.Equal(t, tt.expectedServer, getVal(t, getter, &tt.input, attr.Server))
			assert.Equal(t, tt.expectedServerAddr, getVal(t, getter, &tt.input, attr.ServerAddr))
			assert.Equal(t, tt.expectedClientNamespace, getVal(t, getter, &tt.input, attr.ClientNamespace))
			assert.Equal(t, tt.expectedServerNamespace, getVal(t, getter, &tt.input, attr.ServerNamespace))
		})
	}
}

func getVal[O any](t *testing.T, getters attributes.NamedGetters[*Span, O], span *Span, name attr.Name) O {
	t.Helper()
	getter, ok := getters(name)
	require.Truef(t, ok, "getter %s should be found", name)
	return getter(span)
}
