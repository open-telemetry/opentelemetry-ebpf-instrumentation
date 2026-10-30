// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/exceptions"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestExceptionPipeline(t *testing.T) {
	enabled, disabled := true, false
	for _, tc := range []struct {
		name     string
		defaults bool
		override *bool
		exit     bool
		reuse    bool
		wantLogs int
	}{
		{name: "workload enables capture", override: &enabled, wantLogs: 1},
		{name: "workload disables capture", defaults: true, override: &disabled},
		{name: "exit before decoding", defaults: true, exit: true, wantLogs: 1},
		{name: "PID reused before decoding", defaults: true, exit: true, reuse: true, wantLogs: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := timing.MonoTimeNow() - 10*time.Second
			ebpfcommon.SetupExceptionPipelineTest(t, func() time.Duration { return now })
			filter := ebpfcommon.NewPIDsFilter(&services.DiscoveryConfig{}, slog.Default(), &imetrics.NoopReporter{})
			modes := services.NewExportModes()
			modes.AllowLogs()
			override := services.ExceptionsOverride{Enabled: tc.override}
			service := svc.Attrs{
				UID:         svc.UID{Name: "old-service", Instance: "old-instance"},
				Exceptions:  override.Resolve(services.ExceptionsConfig{Enabled: tc.defaults}),
				ExportModes: modes,
			}
			filter.AllowPID(123, 33, exec.New(exec.Init{Service: service}), ebpfcommon.PIDTypeKProbes)
			capturedAt := now
			records := []*ringbuf.Record{pipelineExceptionRecord(t, capturedAt, "OldError")}

			// The binary record is already captured when discovery reports exit
			// and, optionally, a new process using the same PID and namespace.
			if tc.exit {
				now += time.Second
				filter.BlockPID(123, 33)
			}
			if tc.reuse {
				now += time.Second
				service.UID = svc.UID{Name: "new-service", Instance: "new-instance"}
				filter.AllowPID(123, 33, exec.New(exec.Init{Service: service}), ebpfcommon.PIDTypeKProbes)
				records = append(records, pipelineExceptionRecord(t, now, "NewError"))
			} else if tc.exit {
				// A record captured after exit must be rejected even while the
				// old process metadata remains available for delayed records.
				records = append(records, pipelineExceptionRecord(t, now+time.Second, "AfterExitError"))
			}

			input := msg.NewQueue[[]exceptions.Event]()
			received := make(chan plog.Logs, 2)
			cfg := otelcfg.LogsConfig{
				BatchMaxSize: 16, QueueSize: 32, BatchTimeout: time.Hour,
				LogsExport: func(_ context.Context, logs plog.Logs) error { received <- logs; return nil },
			}
			run, err := otel.ExceptionLogsReceiver(&global.ContextInfo{}, cfg, nil, input)(t.Context())
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { defer close(done); run(ctx) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("exception logs receiver did not stop")
				}
			})

			decodeStarted := time.Now()
			for i, record := range records {
				event, ignore, err := ebpfcommon.ReadExceptionRecord(record, filter)
				require.NoError(t, err)
				require.Equal(t, i >= tc.wantLogs, ignore)
				if !ignore {
					input.Send([]exceptions.Event{event})
				}
			}
			// Closing input drains it and flushes the SDK batch before checking
			// negative cases; no timing-based absence assertion is needed.
			input.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("exception logs receiver did not drain")
			}
			close(received)
			logs := plog.NewLogs()
			for batch := range received {
				batch.ResourceLogs().MoveAndAppendTo(logs.ResourceLogs())
			}
			require.Equal(t, tc.wantLogs, logs.LogRecordCount())
			var kinds []string
			for i := range logs.ResourceLogs().Len() {
				resource := logs.ResourceLogs().At(i)
				require.Equal(t, attr.OBISchemaURL, resource.SchemaUrl())
				record := resource.ScopeLogs().At(0).LogRecords().At(0)
				kind, ok := record.Attributes().Get("exception.type")
				require.True(t, ok)
				kinds = append(kinds, kind.Str())
				name, instance, capture := "old-service", "old-instance", capturedAt
				if kind.Str() == "NewError" {
					name, instance, capture = "new-service", "new-instance", now
				} else {
					require.Equal(t, "OldError", kind.Str())
				}
				for key, want := range map[string]string{"service.name": name, "service.instance.id": instance} {
					value, ok := resource.Resource().Attributes().Get(key)
					require.True(t, ok, key)
					require.Equal(t, want, value.Str(), key)
				}
				require.Equal(t, "exception", record.EventName())
				require.WithinDuration(t, timing.KernelTime(uint64(capture)), record.Timestamp().AsTime(), time.Second)
				require.False(t, record.ObservedTimestamp().AsTime().Before(decodeStarted))
				require.Equal(t, trace.TraceID{1}.String(), record.TraceID().String())
				require.Equal(t, trace.SpanID{2}.String(), record.SpanID().String())
				require.EqualValues(t, trace.FlagsSampled, record.Flags())
			}
			require.ElementsMatch(t, []string{"OldError", "NewError"}[:tc.wantLogs], kinds)
		})
	}
}

func pipelineExceptionRecord(t *testing.T, capture time.Duration, payload string) *ringbuf.Record {
	t.Helper()
	header := ebpfcommon.BpfExceptionEventHeaderT{
		CaptureNs: uint64(capture), PayloadLen: uint32(len(payload)),
		Runtime: uint8(ebpfcommon.BpfExceptionRuntimeK_exceptionRuntimeJava),
		Owner:   uint8(ebpfcommon.BpfExceptionOwnerK_exceptionOwnerOngoing),
	}
	header.Pid.HostPid, header.Pid.UserPid, header.Pid.Ns = 123, 123, 33
	header.Tp.TraceId, header.Tp.SpanId, header.Tp.Flags = [16]uint8{1}, [8]uint8{2}, 1
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &header))
	buf.WriteString(payload)
	return &ringbuf.Record{RawSample: buf.Bytes()}
}
