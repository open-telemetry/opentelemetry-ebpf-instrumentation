// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpuevent

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestRingbufMetrics(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	require.Contains(t, spec.Maps, "gpu_ringbuf_write_stats_storage")
	assert.Equal(t, ebpf.PerCPUArray, spec.Maps["gpu_ringbuf_write_stats_storage"].Type)
	assert.Equal(t, ebpfconvenience.PinInternal, spec.Maps["gpu_ringbuf_write_stats_storage"].Pinning)

	cfg := &obi.Config{}
	tracer := New(nil, cfg, imetrics.NoopReporter{})
	assert.Equal(t, false, tracer.constants()["ringbuf_metrics_enabled"])

	cfg.InternalMetrics.Exporter = imetrics.InternalMetricsExporterPrometheus
	assert.Equal(t, true, tracer.constants()["ringbuf_metrics_enabled"])
}

func TestApplyDeviceIdentityRetainsNameOnlyObservation(t *testing.T) {
	const (
		pid   = app.PID(1234)
		index = uint32(7)
		model = "NVIDIA H20"
	)

	tracer := &Tracer{
		deviceModels: map[app.PID]map[uint32]string{
			pid: {index: model},
		},
	}
	span := request.Span{Pid: request.PidInfo{HostPID: pid}}

	tracer.applyDeviceIdentity(&span, BpfCudaDeviceT{
		Index: index,
		Known: 1,
	})

	assert.True(t, span.CudaDeviceKnown)
	assert.Equal(t, index, span.CudaDeviceIndex)
	assert.Empty(t, span.CudaDeviceUUID)
	assert.Equal(t, model, span.CudaDeviceModel)
}

func TestApplyDeviceIdentityScopesModelToProcess(t *testing.T) {
	tracer := &Tracer{
		deviceModels: map[app.PID]map[uint32]string{
			1234: {7: "NVIDIA H20"},
		},
	}
	span := request.Span{Pid: request.PidInfo{HostPID: 5678}}

	tracer.applyDeviceIdentity(&span, BpfCudaDeviceT{
		Index: 7,
		Known: 1,
	})

	assert.Empty(t, span.CudaDeviceModel)
}

func TestBlockPIDDiscardsDeviceModelsBeforePIDReuse(t *testing.T) {
	const (
		pid   = app.PID(1234)
		index = uint32(7)
		model = "NVIDIA H20"
	)

	tracer := &Tracer{
		pidsFilter: &ebpfcommon.IdentityPidsFilter{},
		deviceModels: map[app.PID]map[uint32]string{
			pid: {index: model},
		},
	}

	tracer.BlockPID(pid, 0)
	tracer.AllowPID(pid, 0, nil)

	span := request.Span{Pid: request.PidInfo{HostPID: pid}}
	tracer.applyDeviceIdentity(&span, BpfCudaDeviceT{
		Index: index,
		Known: 1,
	})

	assert.True(t, span.CudaDeviceKnown)
	assert.Empty(t, span.CudaDeviceModel)
	assert.NotContains(t, tracer.deviceModels, pid)
}
