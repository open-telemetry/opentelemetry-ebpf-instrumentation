// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestZeroFilledFlowSlots(t *testing.T) {
	spec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
			aggregatedFlowsMap: {Type: ebpf.LRUCPUHash},
		}}
	}

	kept := spec()
	zeroFilledFlowSlots(kept, false)
	assert.Equal(t, ebpf.LRUCPUHash, kept.Maps[aggregatedFlowsMap].Type)
	assert.Zero(t, kept.Maps[aggregatedFlowsMap].Flags)

	swapped := spec()
	zeroFilledFlowSlots(swapped, true)
	assert.Equal(t, ebpf.PerCPUHash, swapped.Maps[aggregatedFlowsMap].Type)
	assert.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), swapped.Maps[aggregatedFlowsMap].Flags)
}
