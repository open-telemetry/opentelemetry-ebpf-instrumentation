// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

// SunRPCSyntheticReplyMethod labels reply-only spans where the CALL was not captured.
const SunRPCSyntheticReplyMethod = "reply"

// SunRPCProcedureRouteForExport returns the procedure number string for export.
// Empty for reply-only spans where the CALL was not captured.
func (s *Span) SunRPCProcedureRouteForExport() string {
	if s.Type != EventTypeSunRPCClient && s.Type != EventTypeSunRPCServer {
		return ""
	}
	if s.Method == SunRPCSyntheticReplyMethod {
		return ""
	}
	return s.Route
}

// SunRPCProcedureNameForExport returns a value for onc_rpc.procedure.name when a mapped
// procedure name exists. Empty when Method is unset, duplicates the numeric procedure
// label in Route, or is the synthetic reply-only placeholder.
func (s *Span) SunRPCProcedureNameForExport() string {
	if s.Type != EventTypeSunRPCClient && s.Type != EventTypeSunRPCServer {
		return ""
	}
	if s.Method == "" || s.Method == s.Route || s.Method == SunRPCSyntheticReplyMethod {
		return ""
	}
	return s.Method
}
