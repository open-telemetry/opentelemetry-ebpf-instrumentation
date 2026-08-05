// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sampling

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestBPFConfigLayout(t *testing.T) {
	assert.Equal(t, uintptr(16), unsafe.Sizeof(BPFDelegate{}))
	assert.Equal(t, uintptr(96), unsafe.Sizeof(BPFConfig{}))
	assert.Equal(t, uintptr(88), unsafe.Offsetof(BPFConfig{}.PublicationEpoch))
	assert.Equal(t, uintptr(92), unsafe.Offsetof(BPFConfig{}.Type))
}

func TestBPFProcessReadinessLayout(t *testing.T) {
	assert.Equal(t, uintptr(24), unsafe.Sizeof(BPFProcessReadiness{}))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(BPFProcessReadiness{}.Epoch))
	assert.Equal(t, uintptr(12), unsafe.Offsetof(BPFProcessReadiness{}.ConfigEpoch))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(BPFProcessReadiness{}.Ready))
	assert.Equal(t, uintptr(17), unsafe.Offsetof(BPFProcessReadiness{}.AutoSDKGlobalReady))
}

func TestToBPFConfig(t *testing.T) {
	canonical, err := (&services.SamplerConfig{
		Name: services.SamplerParentBasedTraceIDRatio,
		Arg:  "0.5",
	}).Canonical()
	require.NoError(t, err)

	got := toBPFConfig(canonical)
	assert.Equal(t, uint8(services.SamplerTypeParentBased), got.Type)
	assert.Equal(t, uint8(services.SamplerTypeTraceIDRatio), got.Root.Type)
	assert.Equal(t, uint64(1<<62), got.Root.TraceIDUpperBound)
	assert.Equal(t, uint8(services.SamplerTypeAlwaysOn), got.RemoteParentSampled.Type)
	assert.Equal(t, uint8(services.SamplerTypeAlwaysOff), got.RemoteParentNotSampled.Type)
	assert.Equal(t, uint8(services.SamplerTypeAlwaysOn), got.LocalParentSampled.Type)
	assert.Equal(t, uint8(services.SamplerTypeAlwaysOff), got.LocalParentNotSampled.Type)
}
