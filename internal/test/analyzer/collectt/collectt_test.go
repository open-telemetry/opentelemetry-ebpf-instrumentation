// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collectt_test

import (
	"testing"

	"go.opentelemetry.io/obi/internal/test/analyzer/collectt"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, collectt.Analyzer, "example")
}
