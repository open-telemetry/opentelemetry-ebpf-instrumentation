// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"errors"
	"log/slog"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/processcontext"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/ebpf"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func pclog() *slog.Logger {
	return slog.With("component", "ProcessContextDecorator")
}

func ProcessContextDecoratorProvider(
	input, output *msg.Queue[[]Event[ebpf.Instrumentable]],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		pcd := processContextDecorator{
			in:  input.Subscribe(msg.SubscriberName("ProcessContextDecorator")),
			out: output,
			log: pclog(),
		}
		return pcd.decorate, nil
	}
}

// processContextDecorator enriches discovered processes with context information
// shared by applications through the OTEL_CTX environment mapping, allowing services
// to export resource attributes and metadata without direct instrumentation.
type processContextDecorator struct {
	in  <-chan []Event[ebpf.Instrumentable]
	out *msg.Queue[[]Event[ebpf.Instrumentable]]
	log *slog.Logger
}

func (pcd *processContextDecorator) decorate(ctx context.Context) {
	defer pcd.out.Close()
	swarms.ForEachInput(ctx, pcd.in, pcd.log.Debug, func(instrumentables []Event[ebpf.Instrumentable]) {
		for i := range instrumentables {
			ev := &instrumentables[i]
			if ev.Type == EventCreated {
				pcd.enrichEvent(ev)
			}
		}
		pcd.out.SendCtx(ctx, instrumentables)
	})
}

func (pcd *processContextDecorator) enrichEvent(ev *Event[ebpf.Instrumentable]) {
	pid := ev.Obj.FileInfo.Pid()

	// Find the OTEL_CTX mapping in /proc/<pid>/maps
	mappingAddr, found := pcd.findOTELContextMapping(pid)
	if !found {
		return
	}

	// Read the ProcessContext from remote memory
	rm := remotememory.NewProcessVirtualMemory(libpf.PID(pid))
	info, err := processcontext.Read(mappingAddr, rm, 0, 0)
	if err != nil {
		if errors.Is(err, processcontext.ErrInvalidContext) {
			pcd.log.Debug("no valid ProcessContext in process", "pid", pid)
		} else {
			pcd.log.Debug("failed to read ProcessContext", "pid", pid, "error", err)
		}
		return
	}

	if info.Context == nil {
		return
	}

	if res := info.Context.GetResource(); res != nil {
		for _, kv := range res.GetAttributes() {
			if kv == nil || kv.Key == "" {
				continue
			}
			av := kv.GetValue()
			if av == nil {
				continue
			}
			strVal := av.GetStringValue()
			if strVal == "" {
				if av.Value != nil {
					pcd.log.Debug("attribute value is not a string type", "type", av.Value)
				}
				continue
			}
			pcd.addAttribute(ev, attr.Name(kv.Key), strVal)
		}
	}

	for _, kv := range info.Context.GetExtraAttributes() {
		if kv == nil || kv.Key == "" {
			continue
		}
		av := kv.GetValue()
		if av == nil {
			continue
		}
		strVal := av.GetStringValue()
		if strVal == "" {
			if av.Value != nil {
				pcd.log.Debug("attribute value is not a string type", "type", av.Value)
			}
			continue
		}
		pcd.addAttribute(ev, attr.Name(kv.Key), strVal)
	}
}

func (pcd *processContextDecorator) findOTELContextMapping(pid app.PID) (libpf.Address, bool) {
	maps, err := procs.FindLibMaps(pid)
	if err != nil {
		pcd.log.Debug("failed to read process maps", "pid", pid, "error", err)
		return 0, false
	}

	for _, m := range maps {
		if processcontext.IsContextMapping(m.Perms.Execute, m.Pathname) {
			return libpf.Address(m.StartAddr), true
		}
	}
	return 0, false
}

func (pcd *processContextDecorator) addAttribute(
	ev *Event[ebpf.Instrumentable], key attr.Name, value string,
) {
	fi := ev.Obj.FileInfo
	svcAttrs := fi.ServiceAttrs()

	m := svcAttrs.Metadata
	if m == nil {
		m = make(map[attr.Name]string)
	}
	m[key] = value
	fi.SetMetadata(m)

	// Populate service UID from process context attributes, but only if not
	// already explicitly set. This allows process-level metadata to establish
	// the service identity while preserving any explicit configuration.
	if key == attr.ServiceName && svcAttrs.UID.Name == "" {
		uid := svcAttrs.UID
		uid.Name = value
		fi.SetUID(uid)
	} else if key == attr.ServiceNamespace && svcAttrs.UID.Namespace == "" {
		uid := svcAttrs.UID
		uid.Namespace = value
		fi.SetUID(uid)
	}
}
