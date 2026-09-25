// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpuevent

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestApplyDeviceIdentityRetainsNameOnlyObservation(t *testing.T) {
	const (
		pid   = app.PID(1234)
		index = uint32(7)
		model = "NVIDIA H20"
	)

	tracer := &Tracer{
		deviceModels: map[cudaDeviceKey]string{
			{pid: pid, index: index}: model,
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
		deviceModels: map[cudaDeviceKey]string{
			{pid: 1234, index: 7}: "NVIDIA H20",
		},
	}
	span := request.Span{Pid: request.PidInfo{HostPID: 5678}}

	tracer.applyDeviceIdentity(&span, BpfCudaDeviceT{
		Index: 7,
		Known: 1,
	})

	assert.Empty(t, span.CudaDeviceModel)
}
