// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package logger // import "go.opentelemetry.io/obi/pkg/internal/ebpf/logger"

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/obi"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_info_t -target amd64,arm64 Bpf ../../../../bpf/logger/logger.c -- -I../../../../bpf

type BPFLogInfo BpfLogInfoT

type BPFLogger struct {
	cfg        *obi.Config
	bpfObjects BpfObjects
	closers    []io.Closer
	log        *slog.Logger
}

type Event struct {
	Log string
}

func New(cfg *obi.Config) *BPFLogger {
	log := slog.With("component", "BPFLogger")
	return &BPFLogger{
		log: log,
		cfg: cfg,
	}
}

func (p *BPFLogger) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	if p.cfg.EBPF.BpfDebug {
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
	return nil, errors.New("BPF debug is not enabled")
}

func (p *BPFLogger) constants() map[string]any {
	return map[string]any{"g_bpf_debug": p.cfg.EBPF.BpfDebug}
}

func (p *BPFLogger) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *BPFLogger) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *BPFLogger) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *BPFLogger) SetupTailCalls() {}

func (p *BPFLogger) Run(ctx context.Context) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.DebugEvents,
		p.processLogEvent,
		nil,
		p.log,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)
}

func logDebugEvent(log *slog.Logger, record *ringbuf.Record) {
	event, err := ebpfcommon.ReinterpretCast[BPFLogInfo](record.RawSample)
	if err == nil {
		log.Debug(unix.ByteSliceToString(event.Log[:]),
			"pid", event.Pid,
			"comm", unix.ByteSliceToString(event.Comm[:]))
	}
}

func (p *BPFLogger) processLogEvent(record *ringbuf.Record) (request.Span, bool, error) {
	logDebugEvent(p.log, record)
	return request.Span{}, true, nil
}

// RunDebugEventsReader can be used by any subsystem that loads BPF programs including
// bpf_dbg.h but doesn't go through the main appolly pipeline (e.g. statsolly, netolly).
func RunDebugEventsReader(ctx context.Context, debugEventsMap *ebpf.Map, log *slog.Logger) {
	if debugEventsMap == nil {
		return
	}

	reader, err := ringbuf.NewReader(debugEventsMap)
	if err != nil {
		log.Error("failed to create debug events reader", "error", err)
		return
	}

	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Error("reading debug event", "error", err)
				continue
			}
			logDebugEvent(log, &record)
		}
	}()
}
