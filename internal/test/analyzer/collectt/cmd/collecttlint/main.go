// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// collecttlint runs the collectt analyzer as a standalone checker.
package main

import (
	"go.opentelemetry.io/obi/internal/test/analyzer/collectt"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(collectt.Analyzer)
}
