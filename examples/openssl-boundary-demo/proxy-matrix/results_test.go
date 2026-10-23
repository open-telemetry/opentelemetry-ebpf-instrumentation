// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSameTraceDoesNotProveProxyAncestry(t *testing.T) {
	t.Parallel()
	root := exportedSpan{Trace: "trace", ID: "client", PID: 42, Role: "client", Kind: "client", Path: "/tls/example/0"}
	spans := []exportedSpan{
		root,
		{Trace: "trace", ID: "proxy-server", Parent: "client", Role: "nginx", Kind: "server", Path: root.Path},
		{Trace: "trace", ID: "proxy-client", Parent: "proxy-server", Role: "nginx", Kind: "client", Path: root.Path},
		{Trace: "trace", ID: "origin", Parent: "client", Role: "backend", Kind: "server", Path: root.Path},
	}
	response := observation{Path: root.Path, ClientPID: 42, Traceparent: "00-trace-client-01"}
	result := evaluate(scenario{Name: "example", Proxies: []string{"nginx"}}, []observation{response}, nil, spans)
	require.True(t, result.ContextContinues)
	require.False(t, result.FullAncestry, "a forwarded original header bypasses the proxy client span")
	require.Equal(t, "context-only", result.Support)
}

func TestProxyChainAllowsInternalWorkButRejectsAnotherTrace(t *testing.T) {
	t.Parallel()
	root := exportedSpan{Trace: "trace", ID: "client", Role: "client", Kind: "client", Path: "/tls/example/0"}
	spans := []exportedSpan{
		root,
		{Trace: "trace", ID: "server", Parent: "client", Role: "nginx", Kind: "server", Path: root.Path},
		{Trace: "trace", ID: "processing", Parent: "server", Role: "nginx", Kind: "internal"},
		{Trace: "trace", ID: "outgoing", Parent: "processing", Role: "nginx", Kind: "client", Path: root.Path},
		{Trace: "trace", ID: "origin", Parent: "outgoing", Role: "backend", Kind: "server", Path: root.Path},
	}
	require.True(t, completeChain(spans, root, []string{"nginx"}, false))
	spans[4].Trace = "unrelated"
	require.False(t, completeChain(spans, root, []string{"nginx"}, false))
}

func TestCollectorFileUsesClientURLAndServerPath(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	recorded := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.instance.id","value":{"stringValue":"host:42"}}]},"scopeSpans":[{"spans":[{"traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spanId":"bbbbbbbbbbbbbbbb","kind":3,"attributes":[{"key":"url.full","value":{"stringValue":"https://example/tls/example/0"}}]}]}]},{"resource":{"attributes":[{"key":"service.instance.id","value":{"stringValue":"host:43"}}]},"scopeSpans":[{"spans":[{"traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spanId":"cccccccccccccccc","parentSpanId":"bbbbbbbbbbbbbbbb","kind":2,"attributes":[{"key":"url.path","value":{"stringValue":"/tls/example/0"}}]}]}]}]}`
	require.NoError(t, os.WriteFile(filepath.Join(directory, "traces.jsonl"), []byte(recorded+"\n"), 0o600))
	m := matrix{directory: directory, roles: map[int]string{43: "backend"}}
	spans, err := m.spans()
	require.NoError(t, err)
	require.Len(t, spans, 2)
	require.Equal(t, "/tls/example/0", spans[0].Path)
	require.True(t, completeChain(spans, spans[0], nil, false))
}

func TestAbsoluteProxyTargetNormalization(t *testing.T) {
	t.Parallel()
	for _, target := range []string{
		"/forward/example/0",
		"https://backend:8443/forward/example/0",
		"//backend:8443/forward/example/0",
		"https://obi-proxy-matrixhttps://backend:8443/forward/example/0",
	} {
		require.Equal(t, "/forward/example/0", normalizePath(target))
	}
}
