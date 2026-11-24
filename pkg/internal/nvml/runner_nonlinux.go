// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package nvml // import "go.opentelemetry.io/obi/pkg/internal/nvml"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

// Run reports that GPU device metrics are only available on Linux.
func Run(_ context.Context, _ RunnerConfig, _ func(sample.Sample)) {
	slog.Error("GPU device metrics are only supported on Linux", "component", "nvml.Runner")
}
