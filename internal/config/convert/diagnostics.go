// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

type DiagnosticSeverity string

const (
	DiagnosticSeverityWarning DiagnosticSeverity = "warning"
)

type Diagnostic struct {
	Severity DiagnosticSeverity
	Code     string
	Message  string
	Path     string
}

type exportContext struct {
	diagnostics []Diagnostic
}

func (ctx *exportContext) warn(code, path, message string) {
	ctx.diagnostics = append(ctx.diagnostics, Diagnostic{
		Severity: DiagnosticSeverityWarning,
		Code:     code,
		Message:  message,
		Path:     path,
	})
}
