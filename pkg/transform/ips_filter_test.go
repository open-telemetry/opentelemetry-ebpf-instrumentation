// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestIPsFilter(t *testing.T) {
	tests := []struct {
		name              string
		inputSpans        []request.Span
		expectedSpans     []request.Span
		dropUnresolvedIPs bool
		description       string
	}{
		{
			name: "filter disabled - all spans pass through unchanged",
			inputSpans: []request.Span{
				{
					HostName:  "192.168.1.1",
					Host:      "10.0.0.1",
					PeerName:  "192.168.1.2",
					Peer:      "10.0.0.2",
					Statement: "http;192.168.1.3:8080",
					Service:   svc.Attrs{UID: svc.UID{Name: "test-service"}},
				},
			},
			expectedSpans: []request.Span{
				{
					HostName:  "192.168.1.1",
					Host:      "10.0.0.1",
					PeerName:  "192.168.1.2",
					Peer:      "10.0.0.2",
					Statement: "http;192.168.1.3:8080",
					Service:   svc.Attrs{UID: svc.UID{Name: "test-service"}},
				},
			},
			dropUnresolvedIPs: false,
			description:       "When filtering disabled, all IPs should pass through unchanged",
		},
		{
			name: "filter enabled - IPs are filtered out",
			inputSpans: []request.Span{
				{
					HostName:  "192.168.1.1",
					Host:      "10.0.0.1",
					PeerName:  "192.168.1.2",
					Peer:      "10.0.0.2",
					Statement: "http;192.168.1.3:8080",
					Service:   svc.Attrs{UID: svc.UID{Name: "test-service"}},
				},
			},
			expectedSpans: []request.Span{
				{
					HostName:  "",
					Host:      "",
					PeerName:  "",
					Peer:      "",
					Statement: "http;",
					Service:   svc.Attrs{UID: svc.UID{Name: "test-service"}},
				},
			},
			dropUnresolvedIPs: true,
			description:       "When filtering enabled, all IP addresses should be filtered out",
		},
		{
			name: "mixed hostnames and IPs - only IPs filtered",
			inputSpans: []request.Span{
				{
					HostName:  "example.com",
					Host:      "192.168.1.1",
					PeerName:  "service.local",
					Peer:      "10.0.0.1",
					Statement: "http;frontend:8080",
					Service:   svc.Attrs{UID: svc.UID{Name: "test-service"}},
				},
			},
			expectedSpans: []request.Span{
				{
					HostName:  "example.com",
					Host:      "192.168.1.1", // Should remain because HostName takes precedence
					PeerName:  "service.local",
					Peer:      "10.0.0.1", // Should remain because PeerName takes precedence
					Statement: "http;frontend:8080",
					Service:   svc.Attrs{UID: svc.UID{Name: "test-service"}},
				},
			},
			dropUnresolvedIPs: true,
			description:       "When hostnames available, they should be preserved and IPs should not be filtered",
		},
		{
			name: "IPv6 addresses should be filtered",
			inputSpans: []request.Span{
				{
					HostName:  "2001:db8::1",
					Host:      "::1",
					PeerName:  "2001:db8::2",
					Peer:      "::2",
					Statement: "http;[2001:db8::3]:8080",
					Service:   svc.Attrs{UID: svc.UID{Name: "test-service"}},
				},
			},
			expectedSpans: []request.Span{
				{
					HostName:  "",
					Host:      "",
					PeerName:  "",
					Peer:      "",
					Statement: "http;",
					Service:   svc.Attrs{UID: svc.UID{Name: "test-service"}},
				},
			},
			dropUnresolvedIPs: true,
			description:       "IPv6 addresses should be filtered out when DropUnresolvedIPs is true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create input and output queues
			input := msg.NewQueue[[]request.Span]()
			output := msg.NewQueue[[]request.Span]()

			// Create metrics config
			cfg := &otelcfg.MetricsConfig{
				DropUnresolvedIPs: tt.dropUnresolvedIPs,
			}

			// Create the IP filter instance
			instanceFunc := IPsFilter(cfg, input, output)
			runFunc, err := instanceFunc(context.Background())
			require.NoError(t, err)

			// Subscribe to output BEFORE starting the pipeline
			outputSubscription := output.Subscribe()

			// Run the filter in a goroutine
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				runFunc(ctx)
			}()

			// Send input spans
			input.Send(tt.inputSpans)
			input.Close()

			// Collect output
			var actualSpans []request.Span
			for spans := range outputSubscription {
				actualSpans = append(actualSpans, spans...)
			}

			// Clean up
			cancel()
			<-done

			// Verify results
			assert.Len(t, actualSpans, len(tt.expectedSpans), "Number of spans should match")
			for i, expectedSpan := range tt.expectedSpans {
				if i < len(actualSpans) {
					assert.Equal(t, expectedSpan.HostName, actualSpans[i].HostName, "HostName should match")
					assert.Equal(t, expectedSpan.Host, actualSpans[i].Host, "Host should match")
					assert.Equal(t, expectedSpan.PeerName, actualSpans[i].PeerName, "PeerName should match")
					assert.Equal(t, expectedSpan.Peer, actualSpans[i].Peer, "Peer should match")
					assert.Equal(t, expectedSpan.Statement, actualSpans[i].Statement, "Statement should match")
				}
			}
		})
	}
}

func TestFilterHTTPClientHostFromStatement(t *testing.T) {
	tests := []struct {
		name              string
		statement         string
		expectedStatement string
		description       string
	}{
		{
			name:              "hostname with port should not be filtered",
			statement:         "http;flagd:8013",
			expectedStatement: "http;flagd:8013",
			description:       "Hostname with port should be returned as-is",
		},
		{
			name:              "IP with port should be filtered",
			statement:         "http;10.244.0.3:9153",
			expectedStatement: "http;",
			description:       "IP address with port should be filtered out",
		},
		{
			name:              "pure IP should be filtered",
			statement:         "http;192.168.1.100",
			expectedStatement: "http;",
			description:       "Pure IP address should be filtered out",
		},
		{
			name:              "IPv6 with brackets should be filtered",
			statement:         "http;[2001:db8::1]:8080",
			expectedStatement: "http;",
			description:       "IPv6 address with brackets and port should be filtered out",
		},
		{
			name:              "statement without separator should not be modified",
			statement:         "httpget",
			expectedStatement: "httpget",
			description:       "Statement without scheme separator should remain unchanged",
		},
		{
			name:              "empty statement should remain empty",
			statement:         "",
			expectedStatement: "",
			description:       "Empty statement should remain empty",
		},
		{
			name:              "statement with empty host part",
			statement:         "http;",
			expectedStatement: "http;",
			description:       "Statement with empty host should remain unchanged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := &request.Span{
				Statement: tt.statement,
				Service:   svc.Attrs{UID: svc.UID{Name: "test-service"}},
			}
			filterHTTPClientHostFromStatement(span)
			assert.Equal(t, tt.expectedStatement, span.Statement, tt.description)
		})
	}
}
