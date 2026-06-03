// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSunRPCProcedureNameForExport(t *testing.T) {
	tests := []struct {
		name string
		span Span
		want string
	}{
		{
			name: "mapped name",
			span: Span{Type: EventTypeSunRPCClient, Method: "MOUNTPROC_EXPORT", Route: "5"},
			want: "MOUNTPROC_EXPORT",
		},
		{
			name: "numeric label matches route",
			span: Span{Type: EventTypeSunRPCServer, Method: "0", Route: "0"},
			want: "",
		},
		{
			name: "reply-only synthetic",
			span: Span{Type: EventTypeSunRPCServer, Method: SunRPCSyntheticReplyMethod},
			want: "",
		},
		{
			name: "empty method",
			span: Span{Type: EventTypeSunRPCClient, Route: "1"},
			want: "",
		},
		{
			name: "non-sunrpc span",
			span: Span{Type: EventTypeGRPC, Method: "foo", Route: "bar"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.span.SunRPCProcedureNameForExport())
		})
	}
}

func TestSunRPCProcedureRouteForExport(t *testing.T) {
	tests := []struct {
		name string
		span Span
		want string
	}{
		{
			name: "call span",
			span: Span{Type: EventTypeSunRPCClient, Method: "6", Route: "6"},
			want: "6",
		},
		{
			name: "portmapper null",
			span: Span{Type: EventTypeSunRPCClient, Method: "0", Route: "0"},
			want: "0",
		},
		{
			name: "reply-only synthetic",
			span: Span{Type: EventTypeSunRPCServer, Method: SunRPCSyntheticReplyMethod},
			want: "",
		},
		{
			name: "non-sunrpc",
			span: Span{Type: EventTypeGRPC, Route: "1"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.span.SunRPCProcedureRouteForExport())
		})
	}
}
