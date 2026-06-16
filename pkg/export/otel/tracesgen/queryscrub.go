// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen // import "go.opentelemetry.io/obi/pkg/export/otel/tracesgen"

import "strings"

// scrubQuery replaces the values of sensitiveKeys in the raw query string qs
// with REDACTED, preserving parameter order and non-sensitive values.
// Returns qs unchanged when sensitiveKeys is empty or qs is empty.
func scrubQuery(qs string, sensitiveKeys []string) string {
	if len(sensitiveKeys) == 0 || qs == "" {
		return qs
	}
	redact := make(map[string]struct{}, len(sensitiveKeys))
	for _, k := range sensitiveKeys {
		redact[strings.ToLower(k)] = struct{}{}
	}
	var b strings.Builder
	for i, part := range strings.Split(qs, "&") {
		if i > 0 {
			b.WriteByte('&')
		}
		key, val, hasVal := strings.Cut(part, "=")
		if !hasVal {
			b.WriteString(part)
			continue
		}
		b.WriteString(key)
		b.WriteByte('=')
		if _, sensitive := redact[strings.ToLower(key)]; sensitive {
			b.WriteString("REDACTED")
		} else {
			b.WriteString(val)
		}
	}
	return b.String()
}
