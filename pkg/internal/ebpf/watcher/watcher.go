// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package watcher // import "go.opentelemetry.io/obi/pkg/internal/ebpf/watcher"

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/obi"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type watch_info_t -target amd64,arm64 Bpf ../../../../bpf/watcher/watcher.c -- -I../../../../bpf

type BPFWatchInfo BpfWatchInfoT

type Watcher struct {
	cfg        *obi.Config
	bpfObjects BpfObjects
	closers    []io.Closer
	log        *slog.Logger
	events     chan<- Event
}

type EventType int

const (
	Ready = EventType(iota)
	NewPort
	NewProcess
)

type Event struct {
	Type EventType
	Port uint16
	Pid  uint32
}

func New(cfg *obi.Config, events chan<- Event) *Watcher {
	log := slog.With("component", "watcher.Tracer")
	return &Watcher{
		log:    log,
		events: events,
		cfg:    cfg,
	}
}

func (p *Watcher) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}
	return []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}, nil
}

func (p *Watcher) constants() map[string]any {
	return map[string]any{"g_bpf_debug": p.cfg.EBPF.BpfDebug}
}

func (p *Watcher) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Watcher) KProbes() map[string]ebpfcommon.ProbeDesc {
	kprobes := map[string]ebpfcommon.ProbeDesc{
		"sys_bind": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSysBind,
		},
	}

	return kprobes
}

func (p *Watcher) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Watcher) SetupTailCalls() {}

func (p *Watcher) Run(ctx context.Context) {
	p.events <- Event{Type: Ready}
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.WatchEvents,
		p.processWatchEvent,
		nil,
		p.log,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)
}

func (p *Watcher) processWatchEvent(record *ringbuf.Record) (struct{}, bool, error) {
	var event BPFWatchInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return struct{}{}, true, err
	}
	switch {
	case event.Pid == 0:
		// Can't happen. just ignore
	case event.Port != 0:
		p.log.Debug("New port bind event", "pid", event.Pid, "port", event.Port)
		p.events <- Event{Type: NewPort, Pid: event.Pid, Port: event.Port}
	default:
		p.log.Debug("New process creation event", "pid", event.Pid)
		p.events <- Event{Type: NewProcess, Pid: event.Pid}
	}
	return struct{}{}, true, nil
}
