// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collectt_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"go.opentelemetry.io/obi/internal/test/analyzer/collectt"
)

func TestAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, collectt.Analyzer, "example")
}
