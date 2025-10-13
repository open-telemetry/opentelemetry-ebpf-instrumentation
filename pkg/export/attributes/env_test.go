// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const resAttrs = "service.name=order-api, ,service.version=2.0.0,deployment.environment=staging=a"

func TestParseOTELResourceVariable(t *testing.T) {
	expected := map[string]string{
		"service.name":           "order-api",
		"service.version":        "2.0.0",
		"deployment.environment": "staging=a",
	}

	handler := func(k, v string) {
		require.NotEmpty(t, k)
		require.NotEmpty(t, v)

		e, ok := expected[k]

		require.True(t, ok)
		require.Equal(t, e, v)
	}

	ParseOTELResourceVariable(resAttrs, handler)
}

func TestParseOTELResourceVariable_NoAllocs(t *testing.T) {
	allocs := testing.AllocsPerRun(1000, func() {
		ParseOTELResourceVariable(resAttrs, func(_, _ string) {})
	})

	if allocs != 0 {
		t.Errorf("ParseOTELResourceVariable allocated %v allocs per run; want 0", allocs)
	}
}

func BenchmarkParseOTELResourceVariable(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		ParseOTELResourceVariable(resAttrs, func(_, _ string) {
			// no‑op handler
		})
	}
}
