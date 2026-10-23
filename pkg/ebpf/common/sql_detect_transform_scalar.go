// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !go1.27 || !goexperiment.simd || !(amd64 || arm64)

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

// asciiIndexFold returns the first ASCII case-insensitive match, or -1.
func asciiIndexFold(s, substr []byte) int {
	return asciiIndexFoldScalar(s, substr)
}
