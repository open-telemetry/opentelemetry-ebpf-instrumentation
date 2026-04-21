// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// collecttlint runs the collectt analyzer as a standalone checker.
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"go.opentelemetry.io/obi/internal/test/analyzer/collectt"
)

func main() {
	singlechecker.Main(collectt.Analyzer)
}
