// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tailCallInto(table string) asm.Instructions {
	return asm.Instructions{
		asm.LoadMapPtr(asm.R2, 0).WithReference(table),
		asm.FnTailCall.Call(),
		asm.Return(),
	}
}

func tailCallTable() *ebpf.MapSpec {
	return &ebpf.MapSpec{Type: ebpf.ProgramArray, Contents: []ebpf.MapKV{
		{Key: uint32(0), Value: "target"},
		{Key: uint32(1), Value: "chained"},
		{Key: uint32(2), Value: "listed"},
	}}
}

func uprobeTestSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"jump_table":    tailCallTable(),
			"jump_table_um": tailCallTable(),
			"state":         {Type: ebpf.Hash},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"entry":   {Type: ebpf.Kprobe, SectionName: "uprobe/foo"},
			"ret":     {Type: ebpf.Kprobe, SectionName: "uretprobe/foo"},
			"caller":  {Type: ebpf.Kprobe, SectionName: "uprobe/tail", Instructions: tailCallInto("jump_table")},
			"target":  {Type: ebpf.Kprobe, SectionName: "kprobe", Instructions: tailCallInto("jump_table")},
			"chained": {Type: ebpf.Kprobe, SectionName: "kprobe"},
			"listed":  {Type: ebpf.Kprobe, SectionName: "uprobe/listed"},
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

func TestMarkMultiProgramsGivesMultiProgramsTheirOwnTailCallTable(t *testing.T) {
	spec := uprobeTestSpec()

	markMultiPrograms(spec)

	caller := spec.Programs["caller"]
	assert.Equal(t, ebpf.AttachTraceUprobeMulti, caller.AttachType)
	assert.Equal(t, "jump_table_um", caller.Instructions[0].Reference())

	twin := spec.Maps["jump_table_um"]
	require.NotNil(t, twin)
	assert.Equal(t, ebpf.ProgramArray, twin.Type)
	assert.Equal(t, []ebpf.MapKV{
		{Key: uint32(0), Value: "target_um"},
		{Key: uint32(1), Value: "chained_um"},
		{Key: uint32(2), Value: "listed_um"},
	}, twin.Contents)

	for _, name := range []string{"target_um", "chained_um", "listed_um"} {
		clone := spec.Programs[name]
		require.NotNil(t, clone, name)
		assert.Equal(t, name, clone.Name)
		assert.Equal(t, ebpf.AttachTraceUprobeMulti, clone.AttachType, name)
	}
	assert.Equal(t, "jump_table_um", spec.Programs["target_um"].Instructions[0].Reference())
}

func TestMarkMultiProgramsLeavesTheOriginalTailCallTableAlone(t *testing.T) {
	spec := uprobeTestSpec()

	markMultiPrograms(spec)

	assert.Equal(t, []ebpf.MapKV{
		{Key: uint32(0), Value: "target"},
		{Key: uint32(1), Value: "chained"},
		{Key: uint32(2), Value: "listed"},
	}, spec.Maps["jump_table"].Contents)
	assert.Equal(t, ebpf.AttachNone, spec.Programs["target"].AttachType)
	assert.Equal(t, "jump_table", spec.Programs["target"].Instructions[0].Reference())
	assert.Equal(t, ebpf.AttachNone, spec.Programs["chained"].AttachType)
	// a uprobe program listed in the kprobe table keeps the table's attach type
	assert.Equal(t, ebpf.AttachNone, spec.Programs["listed"].AttachType)
}

// programs sharing a tail-call table must share the table owner's attach type
func TestMarkMultiProgramsKeepsTailCallProgramsAsPerfEventsWithoutTwinTable(t *testing.T) {
	spec := uprobeTestSpec()
	delete(spec.Maps, "jump_table_um")

	markMultiPrograms(spec)

	assert.Equal(t, ebpf.AttachTraceUprobeMulti, spec.Programs["entry"].AttachType)
	assert.Equal(t, ebpf.AttachNone, spec.Programs["caller"].AttachType)
	assert.Equal(t, "jump_table", spec.Programs["caller"].Instructions[0].Reference())
	assert.Len(t, spec.Programs, 8)
}

// a target tail-calling into a second table without a twin must not crash the loader
func TestMarkMultiProgramsSurvivesUntwinnedTableBehindTheTwin(t *testing.T) {
	spec := uprobeTestSpec()
	spec.Maps["other_table"] = &ebpf.MapSpec{Type: ebpf.ProgramArray}
	spec.Programs["target"].Instructions = tailCallInto("other_table")

	markMultiPrograms(spec)

	clone := spec.Programs["target_um"]
	require.NotNil(t, clone)
	assert.Equal(t, "other_table", clone.Instructions[0].Reference())
}

type blockingCloser struct {
	entered chan<- struct{}
	release <-chan struct{}
	err     error
}

func (c blockingCloser) Close() error {
	c.entered <- struct{}{}
	<-c.release
	return c.err
}

// every address of one attachment falls back to its own perf event, and they
// must be released together: a sequential Close would never reach the last one
func TestPerfEventLinksCloseTogether(t *testing.T) {
	const links = 4
	entered := make(chan struct{}, links)
	release := make(chan struct{})

	perf := make(perfEventLinks, 0, links)
	for i := range links {
		perf = append(perf, blockingCloser{
			entered: entered,
			release: release,
			err:     fmt.Errorf("link %d", i),
		})
	}

	closed := make(chan error, 1)
	go func() { closed <- perf.Close() }()

	for i := range links {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d links reached Close: they are released one after another", i, links)
		}
	}
	close(release)

	err := <-closed
	for i := range links {
		require.ErrorContains(t, err, fmt.Sprintf("link %d", i))
	}
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
