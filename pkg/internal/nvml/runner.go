// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvml runs the embedded NVML helper, which reads the state of the
// NVIDIA GPUs of the host.
package nvml // import "go.opentelemetry.io/obi/pkg/internal/nvml"

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

// A sample of a host with many GPUs and processes does not fit the default scanner buffer.
const maxSampleBytes = 4 << 20

// RunnerConfig controls how the embedded NVML helper is executed.
type RunnerConfig struct {
	// Interval is the time between two samples.
	Interval time.Duration
	// HostRoot is the path where OBI sees the root filesystem of the host.
	HostRoot string
}

// readSamples passes to handle each sample that the helper wrote to r, one per line.
func readSamples(r io.Reader, handle func(sample.Sample)) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, maxSampleBytes)

	for scanner.Scan() {
		var s sample.Sample
		if err := json.Unmarshal(scanner.Bytes(), &s); err != nil {
			return fmt.Errorf("decoding an NVML sample: %w", err)
		}

		handle(s)
	}

	return scanner.Err()
}
