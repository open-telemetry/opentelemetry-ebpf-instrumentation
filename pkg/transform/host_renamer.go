// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"log/slog"
	"net"
	"strings"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func uhlog() *slog.Logger {
	return slog.With("component", "transform.UnresolvedHostRenamer")
}

func UnresolvedHostRenamer(unresolved string, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if unresolved == "" {
			return swarm.Bypass(input, output)
		}
		in := input.Subscribe()
		return func(ctx context.Context) {
			defer output.Close()
			for {
				select {
				case <-ctx.Done():
					uhlog().Debug("context done. Stopping")
					return
				case spans, ok := <-in:
					if !ok {
						uhlog().Debug("input channel closed, stopping")
						return
					}
					for i := range spans {
						renameIPsFromSpan(&spans[i], unresolved)
					}
					output.Send(spans)
				}
			}
		}, nil
	}
}

// renameIPsFromSpan removes IP addresses from span fields when they are unresolved
func renameIPsFromSpan(span *request.Span, unknownTag string) {
	// Mark HostName as unknown if it is empty or an IP address
	if span.HostName == "" {
		span.HostName = span.Host
	}
	if net.ParseIP(span.HostName) != nil {
		span.HostName = unknownTag
	}

	// Mark PeerName as unknown if it is empty or an IP address
	if span.PeerName == "" {
		span.PeerName = span.Peer
	}
	if net.ParseIP(span.PeerName) != nil {
		span.PeerName = unknownTag
	}

	// Filter HTTP client host from Statement if it contains IP
	if span.Statement != "" && strings.Contains(span.Statement, request.SchemeHostSeparator) {
		filterHTTPClientHostFromStatement(span)
	}
}

// filterHTTPClientHostFromStatement filters IP addresses from the Statement field for HTTP client spans
func filterHTTPClientHostFromStatement(span *request.Span) {
	if strings.Index(span.Statement, request.SchemeHostSeparator) > 0 {
		schemeHost := strings.Split(span.Statement, request.SchemeHostSeparator)
		if len(schemeHost) >= 2 && schemeHost[1] != "" {
			hostPort := schemeHost[1]

			// Extract host from host:port, handling IPv6 brackets
			host := hostPort
			if strings.HasPrefix(hostPort, "[") {
				// IPv6 with brackets: [2001:db8::1]:8080
				if closeBracket := strings.Index(hostPort, "]"); closeBracket > 0 {
					host = hostPort[1:closeBracket] // Remove brackets
				}
			} else if colonIndex := strings.Index(hostPort, ":"); colonIndex > 0 {
				// IPv4 with port: 192.168.1.1:8080
				host = hostPort[:colonIndex]
			}

			// If host is an IP address, clear the host part from Statement
			if net.ParseIP(host) != nil {
				span.Statement = schemeHost[0] + request.SchemeHostSeparator
			}
		}
	}
}
