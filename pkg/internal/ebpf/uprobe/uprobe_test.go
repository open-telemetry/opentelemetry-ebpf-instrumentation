// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
)

func uprobeTestSpec() *ebpf.CollectionSpec {
	tailCall := asm.Instructions{
		asm.LoadMapPtr(asm.R2, 0).WithReference("jump_table"),
		asm.FnTailCall.Call(),
		asm.Return(),
	}
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"jump_table": {Type: ebpf.ProgramArray, Contents: []ebpf.MapKV{{Key: uint32(0), Value: "target"}}},
			"state":      {Type: ebpf.Hash},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"entry":   {Type: ebpf.Kprobe, SectionName: "uprobe/foo"},
			"ret":     {Type: ebpf.Kprobe, SectionName: "uretprobe/foo"},
			"caller":  {Type: ebpf.Kprobe, SectionName: "uprobe/tail", Instructions: tailCall},
			"target":  {Type: ebpf.Kprobe, SectionName: "uprobe/cont"},
			"kprobe":  {Type: ebpf.Kprobe, SectionName: "kprobe/bar"},
			"sockops": {Type: ebpf.SockOps, SectionName: "sockops"},
		},
	}
}

func TestMarkMultiProgramsMarksUprobePrograms(t *testing.T) {
	spec := uprobeTestSpec()

	markMultiPrograms(spec)

	assert.Equal(t, ebpf.AttachTraceUprobeMulti, spec.Programs["entry"].AttachType)
	assert.Equal(t, ebpf.AttachTraceUprobeMulti, spec.Programs["ret"].AttachType)
	assert.Equal(t, ebpf.AttachNone, spec.Programs["kprobe"].AttachType)
	assert.Equal(t, ebpf.AttachNone, spec.Programs["sockops"].AttachType)
}

// programs sharing a tail-call table must share the table owner's attach type
func TestMarkMultiProgramsKeepsTailCallProgramsAsPerfEvents(t *testing.T) {
	spec := uprobeTestSpec()

	markMultiPrograms(spec)

	assert.Equal(t, ebpf.AttachNone, spec.Programs["caller"].AttachType)
	assert.Equal(t, ebpf.AttachNone, spec.Programs["target"].AttachType)
}

func TestMultiOptionsReplicateRefCtrOffset(t *testing.T) {
	opts := multiOptions(Options{Addresses: []uint64{1, 2, 3}, RefCtrOffset: 0x10, PID: 42})

	assert.Equal(t, []uint64{1, 2, 3}, opts.Addresses)
	assert.Equal(t, []uint64{0x10, 0x10, 0x10}, opts.RefCtrOffsets)
	assert.Equal(t, uint32(42), opts.PID)
}

func TestMultiOptionsWithoutRefCtrOffset(t *testing.T) {
	opts := multiOptions(Options{Addresses: []uint64{7}})

	assert.Equal(t, []uint64{7}, opts.Addresses)
	assert.Nil(t, opts.RefCtrOffsets)
	assert.Zero(t, opts.PID)
}
