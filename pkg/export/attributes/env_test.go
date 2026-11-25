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

func TestParseOTELResourceVariable_PercentDecoding(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  map[string]string
	}{
		{name: "space", input: "team=payments%20core", want: map[string]string{"team": "payments core"}},
		{name: "reserved characters", input: "tags=a%2Cb%3Dc%25", want: map[string]string{"tags": "a,b=c%"}},
		{name: "encoded plus", input: "v=1.0%2B3", want: map[string]string{"v": "1.0+3"}},
		{name: "literal plus", input: "v=a+b", want: map[string]string{"v": "a+b"}},
		{name: "decode once", input: "v=a%2520b", want: map[string]string{"v": "a%20b"}},
		{name: "malformed kept raw", input: "bad=%zz,good=value", want: map[string]string{"bad": "%zz", "good": "value"}},
		{name: "unencoded", input: "service.name=order-api", want: map[string]string{"service.name": "order-api"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]string{}
			ParseOTELResourceVariable(tc.input, func(k, v string) { got[k] = v })
			require.Equal(t, tc.want, got)
		})
	}
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
