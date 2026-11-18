// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics_test

import (
	"testing"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestDotnetSnapshotComparability(t *testing.T) {
	count := uint64(3)
	snapshot := runtimemetrics.DotnetRuntimeMetricSnapshot{
		GCCollections: [runtimemetrics.DotnetGCGenerationCount]*uint64{&count},
	}
	copied := snapshot
	keys := map[runtimemetrics.DotnetRuntimeMetricSnapshot]string{snapshot: "original"}
	if copied != snapshot || keys[copied] != "original" {
		t.Fatal("copying a snapshot must preserve equality and map-key lookup")
	}

	first := runtimemetrics.RuntimeMetricSnapshot{Dotnet: &snapshot, DotnetExceptions: map[string]uint64{"Failure": 1}}
	second := runtimemetrics.RuntimeMetricSnapshot{Dotnet: &copied, DotnetExceptions: map[string]uint64{"Failure": 2, "Other": 1}}
	if *first.Dotnet != *second.Dotnet {
		t.Fatal("exception counts must not change scalar snapshot equality")
	}
}
