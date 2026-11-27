// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import "time"

// GPUDeviceMetrics configures the metrics that describe the NVIDIA GPUs of the
// host, which OBI reads through the NVIDIA Management Library (NVML).
type GPUDeviceMetrics struct {
	Enabled bool

	// Interval is the time between two readings of the GPUs.
	Interval time.Duration `validate:"gt=0"`
}
