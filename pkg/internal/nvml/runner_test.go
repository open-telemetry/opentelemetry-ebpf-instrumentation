// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nvml

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

func TestReadSamples(t *testing.T) {
	output := `{"driver_version":"570.86.15","devices":[{"uuid":"GPU-aaaa","name":"Tesla T4","values":[{"metric":"hw.power","value":68.5}],"processes":[{"pid":4242,"values":[{"metric":"gpu.process.utilization","kind":"general","value":0.5}]}]}]}
{"devices":[{"uuid":"GPU-aaaa"}]}
`

	var samples []sample.Sample
	require.NoError(t, readSamples(strings.NewReader(output), func(s sample.Sample) {
		samples = append(samples, s)
	}))

	require.Len(t, samples, 2)
	assert.Equal(t, sample.Sample{
		DriverVersion: "570.86.15",
		Devices: []sample.Device{{
			UUID:   "GPU-aaaa",
			Name:   "Tesla T4",
			Values: []sample.Value{{Metric: "hw.power", Value: 68.5}},
			Processes: []sample.Process{{
				PID:    4242,
				Values: []sample.Value{{Metric: "gpu.process.utilization", Kind: "general", Value: 0.5}},
			}},
		}},
	}, samples[0])
	assert.Equal(t, sample.Sample{Devices: []sample.Device{{UUID: "GPU-aaaa"}}}, samples[1])
}

func TestReadSamplesRejectsInvalidOutput(t *testing.T) {
	err := readSamples(strings.NewReader("not a sample\n"), func(sample.Sample) {
		t.Fatal("an invalid line must not be reported as a sample")
	})
	require.Error(t, err)
}
