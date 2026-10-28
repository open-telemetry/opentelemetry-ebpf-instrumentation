// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64) && privileged_tests

package discover

import (
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
)

const execveProbeFunction = "net/http.(*Client).do"

func TestExecveUprobe(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires BPF privileges; run in an isolated privileged container")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	launcher, target := buildExecveRepro(t)
	for _, legacy := range []bool{true, false} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			uprobe.ConfigureMulti(legacy)
			t.Cleanup(func() { uprobe.ConfigureMulti(false) })
			child := startExecveRepro(t, launcher, target)
			child.expect(t, 'L')
			bystander := startExecveRepro(t, target, "server")
			bystander.expect(t, 'R')
			pid := app.PID(child.cmd.Process.Pid)
			info, err := findExecElf(&services.ProcessInfo{Pid: pid, ExePath: launcher}, &svc.Attrs{})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, info.ELF().Close()) })
			offset := execveSymbolOffset(t, info.ELF(), execveProbeFunction)
			inst := ebpf.Instrumentable{FileInfo: info, Offsets: &goexec.Offsets{
				Funcs: map[string][]goexec.FuncOffsets{execveProbeFunction: {{Start: offset}}},
			}}
			attacher := traceAttacher{log: slog.Default()}
			executable, ok := attacher.loadExecutable(&inst)
			require.True(t, ok)
			defer executable.Close()
			child.send(t)
			child.expect(t, 'R')

			hits, err := cebpf.NewMap(&cebpf.MapSpec{Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, hits.Close()) })
			spec := &cebpf.CollectionSpec{Programs: map[string]*cebpf.ProgramSpec{
				"repro": {
					Name: "execve_repro", Type: cebpf.Kprobe, SectionName: "uprobe/repro",
					Instructions: asm.Instructions{
						asm.StoreImm(asm.RFP, -4, 0, asm.Word),
						asm.LoadMapPtr(asm.R1, hits.FD()),
						asm.Mov.Reg(asm.R2, asm.RFP),
						asm.Add.Imm(asm.R2, -4),
						asm.FnMapLookupElem.Call(),
						asm.JEq.Imm(asm.R0, 0, "exit"),
						asm.Mov.Imm(asm.R1, 1),
						asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
						asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
						asm.Return(),
					},
					License: "Dual MIT/GPL",
				},
			}}
			uprobe.PrepareSpecs(spec)
			program, err := cebpf.NewProgram(spec.Programs["repro"])
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, program.Close()) })
			tracer := ebpf.NewProcessTracer(ebpf.Go, []ebpf.Tracer{&execveProbeTracer{program: program}}, &obi.Config{}, imetrics.NoopReporter{})
			t.Cleanup(func() { require.NoError(t, tracer.Close()) })
			require.NoError(t, tracer.NewExecutable(executable, &inst))
			require.NoError(t, executable.Close())
			for _, proc := range []*execveReproProcess{child, bystander} {
				proc.send(t)
				proc.expect(t, 'S')
				require.NoError(t, proc.wait(), "execve target and uninstrumented bystander must survive")
			}
			var count uint64
			require.NoError(t, hits.Lookup(uint32(0), &count))
			require.Zero(t, count, "probes must not fire in the replacement binary or its bystander")

			control := startExecveRepro(t, launcher, target)
			control.expect(t, 'L')
			control.send(t)
			control.expect(t, 'R')
			require.NoError(t, hits.Lookup(uint32(0), &count))
			require.Equal(t, uint64(1), count, "the probe must remain attached to the original executable")
			control.send(t)
			control.expect(t, 'S')
			require.NoError(t, control.wait())
		})
	}
}

type execveProbeTracer struct {
	recordingTracer
	program *cebpf.Program
}

func (t *execveProbeTracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return map[string][]*ebpfcommon.ProbeDesc{execveProbeFunction: {{Start: t.program, Required: true}}}
}

func execveSymbolOffset(t *testing.T, file *elf.File, name string) uint64 {
	t.Helper()
	syms, err := file.Symbols()
	require.NoError(t, err)
	for _, sym := range syms {
		if sym.Name != name {
			continue
		}
		for _, prog := range file.Progs {
			if prog.Type == elf.PT_LOAD && sym.Value >= prog.Vaddr && sym.Value < prog.Vaddr+prog.Filesz {
				return sym.Value - prog.Vaddr + prog.Off
			}
		}
	}
	t.Fatalf("symbol %s has no file offset", name)
	return 0
}
