// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package gotracer

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestHTTPServerRequestOffsetsRegistered(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())
	spec, err := LoadBpf()
	require.NoError(t, err)
	mapSpec := spec.Maps["go_offsets_map"].Copy()
	mapSpec.Pinning = ebpf.PinNone
	mapSpec.MaxEntries = 1
	offsetMap, err := ebpf.NewMap(mapSpec)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, offsetMap.Close()) })

	cfg := obi.DefaultConfig
	tracer := New(nil, &cfg, imetrics.NoopReporter{})
	tracer.bpfObjects.GoOffsetsMap = offsetMap
	fileInfo := exec.New(exec.Init{Dev: 1, Ino: 1})
	fields := []goexec.GoOffset{
		goexec.ReqTLSPos,
		goexec.HTTP2ServerReqMethodPos,
		goexec.HTTP2ServerReqURLPos,
		goexec.HTTP2ServerReqTLSPos,
		goexec.HTTP2ResponseWriterStatePos,
		goexec.HTTP2ResponseWriterReqPos,
	}
	for _, tt := range []struct {
		name  string
		value uint64
	}{
		{"missing", missingGoOffset},
		{"present", 48},
		{"zero", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			offsets := &goexec.Offsets{Field: goexec.FieldOffsets{}}
			if tt.value != missingGoOffset {
				for _, field := range fields {
					offsets.Field[field] = tt.value
				}
			}
			tracer.RegisterOffsets(fileInfo, offsets)
			var table BpfOffTableT
			require.NoError(t, offsetMap.Lookup(goOffsetsMapKey(fileInfo), &table))
			for _, field := range fields {
				assert.Equal(t, tt.value, table.Table[field])
			}
		})
	}
}
