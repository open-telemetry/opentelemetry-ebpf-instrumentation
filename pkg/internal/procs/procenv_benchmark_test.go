// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"fmt"
	"testing"
)

var benchmarkEnvMap map[string]string

func BenchmarkEnvStrsToMap(b *testing.B) {
	typical := make([]string, 128)
	for i := range typical {
		typical[i] = fmt.Sprintf("KEY_%d=value_%d", i, i)
	}

	nulPadded := make([]string, 640_000)
	nulPadded[0] = "OTEL_SERVICE_NAME=checkout"

	for _, tc := range []struct {
		name string
		vars []string
	}{
		{name: "Typical128", vars: typical},
		{name: "NULPadded640K", vars: nulPadded},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				benchmarkEnvMap = envStrsToMap(tc.vars)
			}
		})
	}
}
