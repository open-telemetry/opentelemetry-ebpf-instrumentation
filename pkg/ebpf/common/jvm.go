// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"context"
	"log/slog"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

const (
	EventTypeJVMGCHeapSummary = 19 // EVENT_JVM_GC_HEAP_SUMMARY
	EventTypeJVMMemoryPoolGC  = 20 // EVENT_JVM_MEM_POOL_GC
)

type JVMRuntimeMetricSender interface {
	SendJVMRuntimeMetrics(context.Context, []jvmruntime.JVMRuntimeEvent)
}

func HandleJVMRuntimeMetricRecord(
	ctx context.Context,
	eventContext *EBPFEventContext,
	record *ringbuf.Record,
	filter ServiceFilter,
	logger *slog.Logger,
) (bool, error) {
	if record == nil || len(record.RawSample) == 0 {
		return false, nil
	}

	switch record.RawSample[0] {
	case EventTypeJVMGCHeapSummary:
		if eventContext == nil || eventContext.RuntimeMetrics == nil {
			return true, nil
		}
		event, ignore, err := DecodeAndDecorateJVMGCHeapSummaryRecord(record, filter, logger)
		if err != nil || ignore {
			return true, err
		}
		eventContext.RuntimeMetrics.SendJVMRuntimeMetrics(ctx, []jvmruntime.JVMRuntimeEvent{event})
		return true, nil
	case EventTypeJVMMemoryPoolGC:
		if eventContext == nil || eventContext.RuntimeMetrics == nil {
			return true, nil
		}
		events, ignore, err := DecodeAndDecorateJVMMemoryPoolRecord(record, filter, logger)
		if err != nil || ignore || len(events) == 0 {
			return true, err
		}
		eventContext.RuntimeMetrics.SendJVMRuntimeMetrics(ctx, events)
		return true, nil
	default:
		return false, nil
	}
}

func DecodeAndDecorateJVMGCHeapSummaryRecord(
	record *ringbuf.Record,
	filter ServiceFilter,
	logger *slog.Logger,
) (jvmruntime.JVMRuntimeEvent, bool, error) {
	event, err := jvmruntime.DecodeJVMGCHeapSummaryEvent(record.RawSample)
	if err != nil {
		return jvmruntime.JVMRuntimeEvent{}, false, err
	}
	if !decorateJVMRuntimeEvent(filter, &event) {
		return jvmruntime.JVMRuntimeEvent{}, true, nil
	}
	if logger != nil {
		logger.Debug("received JVM GC heap summary event",
			"pid", event.PID,
			"service", event.Service.UID.Name,
			"namespace", event.Service.UID.Namespace,
			"phase", event.GCPhase,
			"value_bytes", event.ValueBytes,
		)
	}
	return event, false, nil
}

func DecodeAndDecorateJVMMemoryPoolRecord(
	record *ringbuf.Record,
	filter ServiceFilter,
	logger *slog.Logger,
) ([]jvmruntime.JVMRuntimeEvent, bool, error) {
	events, err := jvmruntime.DecodeJVMMemoryPoolEvent(record.RawSample)
	if err != nil {
		return nil, false, err
	}

	decorated := events[:0]
	for i := range events {
		if decorateJVMRuntimeEvent(filter, &events[i]) {
			decorated = append(decorated, events[i])
		}
	}
	if len(decorated) == 0 {
		return nil, true, nil
	}

	if logger != nil {
		logger.Debug("received JVM memory pool event",
			"pid", decorated[0].PID,
			"service", decorated[0].Service.UID.Name,
			"namespace", decorated[0].Service.UID.Namespace,
			"pool", decorated[0].PoolName,
			"phase", decorated[0].GCPhase,
			"events", len(decorated),
		)
	}
	return decorated, false, nil
}

func decorateJVMRuntimeEvent(filter ServiceFilter, event *jvmruntime.JVMRuntimeEvent) bool {
	if filter == nil {
		return false
	}
	pids := filter.CurrentPIDs(PIDTypeKProbes)
	namespacePIDs, ok := pids[event.PIDNamespaceID]
	if !ok {
		return false
	}
	if service, ok := namespacePIDs[event.PID]; ok {
		event.Service = service
		return true
	}
	return false
}
