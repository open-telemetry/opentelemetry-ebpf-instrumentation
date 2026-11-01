// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal

import (
	"context"
	"testing"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func SetRunOBIForTest(t *testing.T, run func(context.Context, *obi.Config, *global.ContextInfo, *instrumentations.InstrumentationSelection, ...instrumenter.Option) error) {
	t.Helper()
	previous := runOBI
	runOBI = run
	t.Cleanup(func() { runOBI = previous })
}
