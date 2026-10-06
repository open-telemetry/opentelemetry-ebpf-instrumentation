// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestGRPCMethod(t *testing.T) {
	tests := []struct {
		path     string
		method   string
		original string
	}{
		{path: "/helloworld.Greeter/SayHello", method: "helloworld.Greeter/SayHello"},
		{path: "/Greeter/SayHello", method: "Greeter/SayHello"},
		{path: "/healthz", method: rpcMethodOther, original: "/healthz"},
		{path: "/", method: rpcMethodOther, original: "/"},
		{path: "//SayHello", method: rpcMethodOther, original: "//SayHello"},
		{path: "/helloworld.Greeter/", method: rpcMethodOther, original: "/helloworld.Greeter/"},
		{path: "/a/b/c", method: rpcMethodOther, original: "/a/b/c"},
		{path: "helloworld.Greeter/SayHello", method: rpcMethodOther},
		{path: "*", method: rpcMethodOther},
		{path: "", method: rpcMethodOther},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			for _, eventType := range []EventType{EventTypeGRPC, EventTypeGRPCClient} {
				method, original := GRPCMethod(&Span{Type: eventType, Path: tt.path})
				assert.Equal(t, tt.method, method)
				assert.Equal(t, tt.original, original)
			}
		})
	}
}

func TestGRPCMethodUnimplemented(t *testing.T) {
	server := &Span{Type: EventTypeGRPC, Path: "/helloworld.Greeter/SayHello", Status: grpcStatusCodeUnimplemented}
	method, original := GRPCMethod(server)
	assert.Equal(t, rpcMethodOther, method)
	assert.Equal(t, "/helloworld.Greeter/SayHello", original)
	assert.Equal(t, "grpc", server.TraceName())

	client := &Span{Type: EventTypeGRPCClient, Path: "/helloworld.Greeter/SayHello", Status: grpcStatusCodeUnimplemented}
	method, original = GRPCMethod(client)
	assert.Equal(t, "helloworld.Greeter/SayHello", method)
	assert.Empty(t, original)
	assert.Equal(t, "helloworld.Greeter/SayHello", client.TraceName())

	unread := &Span{Type: EventTypeGRPC, Path: "*", Status: grpcStatusCodeUnimplemented}
	method, original = GRPCMethod(unread)
	assert.Equal(t, rpcMethodOther, method)
	assert.Empty(t, original)
}

func TestGRPCMethodGetters(t *testing.T) {
	otelGetter, ok := spanOTELGetters(attr.RPCMethod)
	require.True(t, ok)
	promGetter := spanPromGetters(attr.RPCMethod)

	for _, eventType := range []EventType{EventTypeGRPC, EventTypeGRPCClient} {
		span := &Span{Type: eventType, Path: "/helloworld.Greeter/SayHello"}
		assert.Equal(t, "helloworld.Greeter/SayHello", otelGetter(span).Value.AsString())
		assert.Equal(t, "helloworld.Greeter/SayHello", promGetter(span))

		unread := &Span{Type: eventType, Path: "*"}
		assert.Equal(t, rpcMethodOther, otelGetter(unread).Value.AsString())
		assert.Equal(t, rpcMethodOther, promGetter(unread))
	}

	unimplemented := &Span{Type: EventTypeGRPC, Path: "/helloworld.Greeter/SayHello", Status: grpcStatusCodeUnimplemented}
	assert.Equal(t, rpcMethodOther, otelGetter(unimplemented).Value.AsString())
	assert.Equal(t, rpcMethodOther, promGetter(unimplemented))
}

func TestGRPCDebugAttributes(t *testing.T) {
	attrs := spanAttributes(&Span{Type: EventTypeGRPC, Path: "/helloworld.Greeter/SayHello"})
	assert.Equal(t, "helloworld.Greeter/SayHello", attrs["method"])
	assert.NotContains(t, attrs, "methodOriginal")

	attrs = spanAttributes(&Span{Type: EventTypeGRPCClient, Path: "/healthz"})
	assert.Equal(t, rpcMethodOther, attrs["method"])
	assert.Equal(t, "/healthz", attrs["methodOriginal"])
}
