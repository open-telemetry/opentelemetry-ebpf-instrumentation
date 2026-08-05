// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type recordingHTTP2ConnectionWriter struct {
	calls int
	key   *BpfPidConnectionInfoT
	value BpfHttp2ConnInfoDataT
	flags ebpf.MapUpdateFlags
	err   error
}

type recordingConnectionTrackerReader struct {
	key   *BpfConnectionInfoT
	value BpfTrackedConnectionT
	err   error
}

func (r *recordingConnectionTrackerReader) Lookup(key, valueOut any) error {
	r.key = key.(*BpfConnectionInfoT)
	if r.err != nil {
		return r.err
	}
	*(valueOut.(*BpfTrackedConnectionT)) = r.value
	return nil
}

func (w *recordingHTTP2ConnectionWriter) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	w.calls++
	w.key = key.(*BpfPidConnectionInfoT)
	w.value = value.(BpfHttp2ConnInfoDataT)
	w.flags = flags
	return w.err
}

func TestWriteMisclassifiedHTTP2Connection(t *testing.T) {
	const (
		hostPID           = uint32(901)
		userPID           = uint32(42)
		ns                = uint32(7)
		admittedStartTime = uint64(1_730_000_000)
		exactStartTime    = uint64(1_734_567_890)
		requestStartTime  = uint64(1_500_000_000)
		connectionTime    = uint64(1_100_000_000)
		connectionNetns   = uint32(4026532001)
	)

	tracer := &Tracer{processHostStartTime: map[genericProcessKey]uint64{}}
	tcpInfo := &ebpfcommon.TCPRequestInfo{}
	tcpInfo.Pid.HostPid = hostPID
	tcpInfo.Pid.UserPid = userPID
	tcpInfo.Pid.Ns = ns
	tcpInfo.StartMonotimeNs = requestStartTime
	tcpInfo.ProcessStartTime = exactStartTime
	tcpInfo.ConnectionTime = connectionTime
	tcpInfo.ConnectionNetns = connectionNetns
	tcpInfo.Ssl = 1
	tcpInfo.ConnInfo.S_port = 40001
	tcpInfo.ConnInfo.D_port = 443

	writer := &recordingHTTP2ConnectionWriter{}
	tracker := &recordingConnectionTrackerReader{
		value: BpfTrackedConnectionT{Time: connectionTime, Netns: connectionNetns},
	}
	written, err := tracer.writeMisclassifiedHTTP2Connection(writer, tracker, tcpInfo)
	require.NoError(t, err)
	assert.False(t, written)
	assert.Zero(t, writer.calls, "an unadmitted process must not create a connection generation")

	processKey := genericProcessKey{pid: app.PID(hostPID), ns: ns}
	tracer.processHostStartTime[processKey] = admittedStartTime
	tcpInfo.ConnectionTime = 0
	written, err = tracer.writeMisclassifiedHTTP2Connection(writer, tracker, tcpInfo)
	require.NoError(t, err)
	assert.False(t, written)
	assert.Zero(t, writer.calls, "an event without a socket-generation identity is rejected")

	tcpInfo.ConnectionTime = connectionTime
	tcpInfo.ConnectionNetns = 0
	written, err = tracer.writeMisclassifiedHTTP2Connection(writer, tracker, tcpInfo)
	require.NoError(t, err)
	assert.False(t, written)
	assert.Zero(t, writer.calls, "an event without a network namespace identity is rejected")

	tcpInfo.ConnectionNetns = connectionNetns
	tcpInfo.ProcessStartTime = exactStartTime + processClockTickNanoseconds
	written, err = tracer.writeMisclassifiedHTTP2Connection(writer, tracker, tcpInfo)
	require.NoError(t, err)
	assert.False(t, written)
	assert.Zero(t, writer.calls, "an event outside the admitted process tick is rejected")

	tcpInfo.ProcessStartTime = exactStartTime
	written, err = tracer.writeMisclassifiedHTTP2Connection(writer, tracker, tcpInfo)
	require.NoError(t, err)
	assert.True(t, written)
	require.Equal(t, 1, writer.calls)
	require.NotNil(t, writer.key)
	assert.Equal(t, hostPID, writer.key.Pid, "the BPF key uses the host PID")
	assert.Equal(t, tcpInfo.ConnInfo.S_port, writer.key.Conn.S_port)
	assert.Equal(t, tcpInfo.ConnInfo.D_port, writer.key.Conn.D_port)
	require.NotNil(t, tracker.key)
	assert.Equal(t, writer.key.Conn, *tracker.key,
		"tracker validation and connection insertion use the same canonical key")
	assert.Equal(t, requestStartTime, writer.value.Id, "request time is the connection generation")
	assert.Equal(t, exactStartTime, writer.value.ProcessStartTime,
		"the BPF value receives exact kernel identity, not the rounded admission time")
	assert.Equal(t, connectionTime, writer.value.ConnectionTime)
	assert.Equal(t, tcpInfo.Ssl, writer.value.Flags)
	assert.Equal(t, ebpf.UpdateNoExist, writer.flags)
	assert.Equal(t, uintptr(32), unsafe.Sizeof(writer.value), "shared map value stays compact")
}

func TestWriteMisclassifiedHTTP2ConnectionPutFailure(t *testing.T) {
	putErr := errors.New("put failed")
	writer := &recordingHTTP2ConnectionWriter{err: putErr}
	const (
		pid               = uint32(44)
		ns                = uint32(8)
		admittedStartTime = uint64(2_000_000_000)
		exactStartTime    = uint64(2_001_234_567)
	)
	tracer := &Tracer{
		processHostStartTime: map[genericProcessKey]uint64{
			{pid: app.PID(904), ns: ns}: admittedStartTime,
		},
	}
	tcpInfo := &ebpfcommon.TCPRequestInfo{
		StartMonotimeNs:  exactStartTime + 1,
		ProcessStartTime: exactStartTime,
		ConnectionTime:   exactStartTime - 1,
		ConnectionNetns:  4026532002,
	}
	tcpInfo.Pid.HostPid = 904
	tcpInfo.Pid.UserPid = pid
	tcpInfo.Pid.Ns = ns

	tracker := &recordingConnectionTrackerReader{
		value: BpfTrackedConnectionT{Time: tcpInfo.ConnectionTime, Netns: tcpInfo.ConnectionNetns},
	}
	written, err := tracer.writeMisclassifiedHTTP2Connection(writer, tracker, tcpInfo)
	assert.True(t, written, "a failed map write is still an attempted admissible update")
	require.ErrorIs(t, err, putErr)
	assert.Equal(t, 1, writer.calls)
}

func TestWriteMisclassifiedHTTP2ConnectionDuplicateIsBenign(t *testing.T) {
	const (
		pid               = uint32(45)
		ns                = uint32(9)
		admittedStartTime = uint64(3_000_000_000)
		exactStartTime    = uint64(3_004_567_890)
	)
	writer := &recordingHTTP2ConnectionWriter{err: syscall.EEXIST}
	tracer := &Tracer{processHostStartTime: map[genericProcessKey]uint64{
		{pid: app.PID(905), ns: ns}: admittedStartTime,
	}}
	tcpInfo := &ebpfcommon.TCPRequestInfo{
		StartMonotimeNs:  exactStartTime + 1,
		ProcessStartTime: exactStartTime,
		ConnectionTime:   exactStartTime - 1,
		ConnectionNetns:  4026532003,
	}
	tcpInfo.Pid.HostPid = 905
	tcpInfo.Pid.UserPid = pid
	tcpInfo.Pid.Ns = ns

	tracker := &recordingConnectionTrackerReader{
		value: BpfTrackedConnectionT{Time: tcpInfo.ConnectionTime, Netns: tcpInfo.ConnectionNetns},
	}
	written, err := tracer.writeMisclassifiedHTTP2Connection(writer, tracker, tcpInfo)
	require.NoError(t, err)
	assert.False(t, written, "an existing generation is left under BPF-side ownership")
	assert.Equal(t, 1, writer.calls)
	assert.Equal(t, ebpf.UpdateNoExist, writer.flags)
}

func TestWriteMisclassifiedHTTP2ConnectionRequiresExactTrackerGeneration(t *testing.T) {
	const (
		hostPID           = uint32(906)
		ns                = uint32(10)
		admittedStartTime = uint64(4_000_000_000)
		exactStartTime    = uint64(4_001_234_567)
		connectionTime    = uint64(3_900_000_000)
	)
	tracer := &Tracer{processHostStartTime: map[genericProcessKey]uint64{
		{pid: app.PID(hostPID), ns: ns}: admittedStartTime,
	}}
	tcpInfo := &ebpfcommon.TCPRequestInfo{
		StartMonotimeNs:  exactStartTime + 1,
		ProcessStartTime: exactStartTime,
		ConnectionTime:   connectionTime,
		ConnectionNetns:  4026532004,
	}
	tcpInfo.Pid.HostPid = hostPID
	tcpInfo.Pid.Ns = ns
	writer := &recordingHTTP2ConnectionWriter{}
	testErr := errors.New("tracker read failed")

	for _, test := range []struct {
		name    string
		tracker *recordingConnectionTrackerReader
		wantErr error
	}{
		{name: "missing", tracker: &recordingConnectionTrackerReader{err: ebpf.ErrKeyNotExist}},
		{name: "mismatch", tracker: &recordingConnectionTrackerReader{
			value: BpfTrackedConnectionT{Time: connectionTime + 1, Netns: tcpInfo.ConnectionNetns},
		}},
		{name: "network namespace mismatch", tracker: &recordingConnectionTrackerReader{
			value: BpfTrackedConnectionT{Time: connectionTime, Netns: tcpInfo.ConnectionNetns + 1},
		}},
		{name: "error", tracker: &recordingConnectionTrackerReader{err: testErr}, wantErr: testErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer.calls = 0
			written, err := tracer.writeMisclassifiedHTTP2Connection(writer, test.tracker, tcpInfo)
			assert.False(t, written)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Zero(t, writer.calls)
		})
	}
}

func TestCanonicalHTTP2ConnectionInfoMatchesBPFOrdering(t *testing.T) {
	tests := []struct {
		name       string
		sourcePort uint16
		destPort   uint16
		sourceWord byte
		destWord   byte
		swapped    bool
	}{
		{name: "source ephemeral", sourcePort: 40000, destPort: 443},
		{name: "destination ephemeral", sourcePort: 443, destPort: 40000, swapped: true},
		{name: "larger destination", sourcePort: 1234, destPort: 5678, swapped: true},
		{
			name: "equal ports source address after", sourcePort: 8080, destPort: 8080,
			sourceWord: 2, destWord: 1, swapped: true,
		},
		{
			name: "equal ports source address before", sourcePort: 8080, destPort: 8080,
			sourceWord: 1, destWord: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src := ebpfcommon.BpfConnectionInfoT{
				S_port: test.sourcePort,
				D_port: test.destPort,
			}
			src.S_addr[0] = test.sourceWord
			src.D_addr[0] = test.destWord
			got := canonicalHTTP2ConnectionInfo(src)
			if test.swapped {
				assert.Equal(t, test.destPort, got.S_port)
				assert.Equal(t, test.sourcePort, got.D_port)
				assert.Equal(t, test.destWord, got.S_addr[0])
				assert.Equal(t, test.sourceWord, got.D_addr[0])
			} else {
				assert.Equal(t, test.sourcePort, got.S_port)
				assert.Equal(t, test.destPort, got.D_port)
				assert.Equal(t, test.sourceWord, got.S_addr[0])
				assert.Equal(t, test.destWord, got.D_addr[0])
			}
		})
	}
}

func TestProcessStartTimeHostAliasLifecycle(t *testing.T) {
	const (
		discoveryPID = app.PID(41)
		hostPID      = app.PID(901)
		ns           = uint32(7)
		startTime    = uint64(1_730_000_000)
	)
	originalKey := genericProcessKey{pid: discoveryPID, ns: ns}
	hostKey := genericProcessKey{pid: hostPID, ns: ns}
	tracer := &Tracer{
		processStartTime:     map[genericProcessKey]uint64{},
		processHostStartTime: map[genericProcessKey]uint64{},
		processHostAlias:     map[genericProcessKey]genericProcessKey{},
		processHostOwner:     map[genericProcessKey]genericProcessKey{},
	}

	tracer.rememberProcessStartTime(originalKey, hostPID, startTime)
	assert.Equal(t, startTime, tracer.processStartTime[originalKey])
	assert.Equal(t, startTime, tracer.processHostStartTime[hostKey])
	assert.Equal(t, hostKey, tracer.processHostAlias[originalKey])

	tracer.deleteProcessStartTime(originalKey, startTime)
	assert.NotContains(t, tracer.processStartTime, originalKey)
	assert.NotContains(t, tracer.processHostStartTime, hostKey)
	assert.NotContains(t, tracer.processHostAlias, originalKey)
}

func TestProcessStartTimeHostAliasesDoNotCollideWithDiscoveryKeys(t *testing.T) {
	const ns = uint32(5)
	a := genericProcessKey{pid: 41, ns: ns}
	aHost := genericProcessKey{pid: 1000, ns: ns}
	b := genericProcessKey{pid: 1000, ns: ns}
	bHost := genericProcessKey{pid: 2000, ns: ns}

	newTracer := func() *Tracer {
		return &Tracer{
			processStartTime:     map[genericProcessKey]uint64{},
			processHostStartTime: map[genericProcessKey]uint64{},
			processHostAlias:     map[genericProcessKey]genericProcessKey{},
			processHostOwner:     map[genericProcessKey]genericProcessKey{},
		}
	}
	for _, deleteAFirst := range []bool{true, false} {
		tracer := newTracer()
		tracer.rememberProcessStartTime(a, aHost.pid, 100)
		tracer.rememberProcessStartTime(b, bHost.pid, 200)
		assert.Equal(t, uint64(200), tracer.processStartTime[b],
			"B's discovery key is independent from A's equal-valued host key")
		assert.Equal(t, uint64(100), tracer.processHostStartTime[aHost])
		if deleteAFirst {
			tracer.deleteProcessStartTime(a, 100)
			assert.Equal(t, uint64(200), tracer.processStartTime[b])
			assert.Equal(t, uint64(200), tracer.processHostStartTime[bHost])
			tracer.deleteProcessStartTime(b, 200)
		} else {
			tracer.deleteProcessStartTime(b, 200)
			assert.Equal(t, uint64(100), tracer.processHostStartTime[aHost])
			tracer.deleteProcessStartTime(a, 100)
		}
		assert.Empty(t, tracer.processStartTime)
		assert.Empty(t, tracer.processHostStartTime)
	}

	tracer := newTracer()
	tracer.rememberProcessStartTime(a, aHost.pid, 100)
	tracer.rememberProcessStartTime(a, bHost.pid, 300)
	assert.NotContains(t, tracer.processHostStartTime, aHost)
	assert.Equal(t, uint64(300), tracer.processHostStartTime[bHost])
}

func TestProcessStartTimeResolverFailureDisablesRecoveryAlias(t *testing.T) {
	existingOwner := genericProcessKey{pid: 50, ns: 5}
	existingHost := genericProcessKey{pid: 1000, ns: 5}
	failed := genericProcessKey{pid: 51, ns: 5}
	tracer := &Tracer{
		processStartTime:     map[genericProcessKey]uint64{},
		processHostStartTime: map[genericProcessKey]uint64{},
		processHostAlias:     map[genericProcessKey]genericProcessKey{},
		processHostOwner:     map[genericProcessKey]genericProcessKey{},
		resolveHostPID: func(app.PID) (uint32, error) {
			return 0, errors.New("resolve failed")
		},
	}
	tracer.rememberProcessStartTime(existingOwner, existingHost.pid, 100)
	tracer.recordProcessStartTime(failed, 200)

	assert.Equal(t, uint64(200), tracer.processStartTime[failed])
	assert.NotContains(t, tracer.processHostAlias, failed)
	assert.Equal(t, uint64(100), tracer.processHostStartTime[existingHost])
	assert.Equal(t, existingOwner, tracer.processHostOwner[existingHost])
}

func TestBitPositionCalculation(t *testing.T) {
	for _, v := range [][4]uint32{
		{0, 1, 0, 1},
		{0, 2, 0, 2},
		{0, 65, 1, 1},
		{0, 66, 1, 2},
		{0, primeHash, 0, 0},
		{0, primeHash + 1, 0, 1},
	} {
		k := makeKey(v[0], v[1])
		segment, bit := pidSegmentBit(k)
		assert.Equal(t, segment, v[2])
		assert.Equal(t, bit, v[3])
	}
}

func makeKey(first, second uint32) uint64 {
	return (uint64(first) << 32) | uint64(second)
}

// Mirrors the _Static_assert in bpf/pid/pid.h.
func TestPidFilterIndexSpaceFitsMap(t *testing.T) {
	highestSegment := (primeHash - 1) / 64

	assert.Less(t, highestSegment, maxConcurrentPids,
		"primeHash %d needs %d segments but valid_pids holds %d",
		primeHash, highestSegment+1, maxConcurrentPids)

	// buildPidFilter must allocate a slot for every reachable segment.
	assert.Len(t, (&Tracer{pidsFilter: fakeServiceFilter{}}).buildPidFilter(), maxConcurrentPids)
}

func TestParseJVMMemoryPoolRecordDecoratesServiceByPIDNamespace(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	currentPIDsCalls := 0
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				7:  {1234: {UID: svc.UID{Name: "wrong"}}},
				42: {1234: service},
			},
			currentPIDsCalls: &currentPIDsCalls,
		},
	}

	events, ignore, err := tracer.parseJVMMemoryPoolRecord(&ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			Timestamp:  123,
			NsPid:      1234,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			MaxSize:    300,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, events, 4)
	for _, event := range events {
		assert.Equal(t, service, event.Service)
	}
	assert.Equal(t, 1, currentPIDsCalls)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsed, events[0].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryCommitted, events[1].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryLimit, events[2].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsedAfterLastGC, events[3].Kind)
}

func TestParseJVMMemoryPoolRecordIgnoresUnknownPID(t *testing.T) {
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: {UID: svc.UID{Name: "orders"}}},
			},
		},
	}

	events, ignore, err := tracer.parseJVMMemoryPoolRecord(&ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			NsPid:      9999,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Empty(t, events)
}

func TestProcessSharedRingbufRecordConsumesJVMRuntimeMetricRecordsWithoutForwarding(t *testing.T) {
	for _, tt := range []struct {
		name    string
		enabled bool
	}{
		{name: "metrics disabled"},
		{name: "queue missing", enabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracer := &Tracer{cfg: &obi.Config{}}
			if tt.enabled {
				tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime
			}

			span, ignore, err := tracer.processSharedRingbufRecord(context.Background(), nil, &tracer.cfg.EBPF, &ringbuf.Record{
				RawSample: []byte{ebpfcommon.EventTypeJVMMemoryPoolGC},
			})

			require.NoError(t, err)
			assert.True(t, ignore)
			assert.Empty(t, span)
		})
	}
}

func TestProcessSharedRingbufRecordDispatchesRegisteredInternalEvent(t *testing.T) {
	const testInternalEventType uint8 = 0xfe

	eventContext := ebpfcommon.NewEBPFEventContext()
	handled := false
	eventContext.RegisterInternalEventHandler(
		testInternalEventType,
		func(*ringbuf.Record) error {
			handled = true
			return nil
		},
	)
	tracer := &Tracer{
		cfg:      &obi.Config{},
		eventCtx: eventContext,
	}

	span, ignore, err := tracer.processSharedRingbufRecord(
		context.Background(),
		nil,
		&tracer.cfg.EBPF,
		&ringbuf.Record{RawSample: []byte{testInternalEventType}},
	)

	require.NoError(t, err)
	assert.True(t, handled)
	assert.True(t, ignore)
	assert.Empty(t, span)
}

func TestProcessSharedRingbufRecordDispatchesJVMMemoryPoolRecord(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	runtimeMetrics := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := runtimeMetrics.Subscribe(msg.SubscriberName("jvm-test"))
	tracer := &Tracer{
		cfg: &obi.Config{},
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: service},
			},
		},
		eventCtx: &ebpfcommon.EBPFEventContext{RuntimeMetrics: runtimemetrics.NewQueueSender(runtimeMetrics)},
	}
	tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime

	span, ignore, err := tracer.processSharedRingbufRecord(context.Background(), nil, &tracer.cfg.EBPF, &ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			Type:       ebpfcommon.EventTypeJVMMemoryPoolGC,
			Timestamp:  100,
			NsPid:      1234,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			MaxSize:    300,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Empty(t, span)

	batch := readJVMTestBatch(t, received)
	require.Len(t, batch, 4)
	for _, snapshot := range batch {
		assert.Equal(t, service, snapshot.Service)
		require.NotNil(t, snapshot.JVM)
	}
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsed, batch[0].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryCommitted, batch[1].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryLimit, batch[2].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsedAfterLastGC, batch[3].JVM.Kind)
}

func TestJVMBPFMapsAreInternallyPinnedAndUseSharedEventsRingBuffer(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	require.NotContains(t, spec.Maps, "jvm_gc_heap_summary_events")
	require.NotContains(t, spec.Maps, "jvm_mem_pool_gc_events")
	require.NotContains(t, spec.Maps, "jvm_heap_summary_samples")

	for _, name := range []string{
		"jvm_mem_pool_samples",
		"obi_usdt_specs",
		"obi_usdt_ip_to_spec_id",
	} {
		require.Contains(t, spec.Maps, name)
		assert.Equal(t, ebpfconvenience.PinInternal, spec.Maps[name].Pinning)
	}
	assert.Equal(t, ebpf.LRUHash, spec.Maps["obi_usdt_ip_to_spec_id"].Type)
}

func TestHTTP2ConnectionMapUsesCompactExactGenerationValue(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	connectionMap := spec.Maps["ongoing_http2_connections"]
	require.NotNil(t, connectionMap)
	assert.Equal(t, ebpf.Hash, connectionMap.Type, "generation-checked deletes require non-LRU storage")
	assert.Equal(t, uint32(32), connectionMap.ValueSize)
	assert.Equal(t, uintptr(32), unsafe.Sizeof(BpfHttp2ConnInfoDataT{}))
}

func TestJVMRuntimeMetricsExposeHotSpotUSDTProbes(t *testing.T) {
	tracer := Tracer{cfg: &obi.Config{}}
	assert.Empty(t, tracer.USDTProbes())

	tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime
	assert.NotContains(t, tracer.UProbes(), "libjvm.so")

	probes := tracer.USDTProbes()

	require.Contains(t, probes, "libjvm.so")
	require.Len(t, probes["libjvm.so"], 2)
	assert.Equal(t, "hotspot", probes["libjvm.so"][0].Provider)
	assert.Equal(t, "mem__pool__gc__begin", probes["libjvm.so"][0].Name)
	assert.Equal(t, "hotspot", probes["libjvm.so"][1].Provider)
	assert.Equal(t, "mem__pool__gc__end", probes["libjvm.so"][1].Name)
}

func TestJVMRuntimeMetricsConstantOverridesUseApplicationRuntimeAsFeatureGate(t *testing.T) {
	for _, tt := range []struct {
		name             string
		configure        func(*obi.Config)
		samplingInterval time.Duration
		expectedInterval uint64
	}{
		{name: "disabled", samplingInterval: time.Second},
		{
			name: "enabled globally",
			configure: func(cfg *obi.Config) {
				cfg.Metrics.Features = export.FeatureApplicationRuntime
			},
			samplingInterval: 250 * time.Millisecond,
			expectedInterval: uint64((250 * time.Millisecond).Nanoseconds()),
		},
		{
			name: "enabled for instrument selector",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Instrument = services.GlobDefinitionCriteria{
					{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureApplicationRuntime}},
				}
			},
			samplingInterval: 500 * time.Millisecond,
			expectedInterval: uint64((500 * time.Millisecond).Nanoseconds()),
		},
		{
			name: "enabled for deprecated services selector",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Services = services.RegexDefinitionCriteria{
					{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureApplicationRuntime}},
				}
			},
			samplingInterval: 750 * time.Millisecond,
			expectedInterval: uint64((750 * time.Millisecond).Nanoseconds()),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracer := Tracer{cfg: &obi.Config{}}
			if tt.configure != nil {
				tt.configure(tracer.cfg)
			}
			tracer.cfg.JVMRuntimeMetrics.SamplingInterval = tt.samplingInterval

			overrides := tracer.constants()

			assert.Equal(t, tt.expectedInterval, overrides["jvm_sampling_interval_ns"])
		})
	}
}

func TestTraceDependentSamplingEnablesTraceparentParsingWithoutPropagation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		sampler services.SamplerConfig
	}{
		{name: "default", sampler: services.SamplerConfig{}},
		{name: "always on root", sampler: services.SamplerConfig{Name: services.SamplerParentBasedAlwaysOn}},
		{name: "always off root", sampler: services.SamplerConfig{Name: services.SamplerParentBasedAlwaysOff}},
		{
			name: "ratio root",
			sampler: services.SamplerConfig{
				Name: services.SamplerParentBasedTraceIDRatio,
				Arg:  "0.25",
			},
		},
		{
			name: "direct ratio",
			sampler: services.SamplerConfig{
				Name: services.SamplerTraceIDRatio,
				Arg:  "0.25",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := traceparentParsingTestConfig()
			cfg.Traces.SamplerConfig = tt.sampler

			constants := New(fakeServiceFilter{}, &cfg, nil).constants()

			assert.Equal(t, int32(1), constants["capture_header_buffer"])
			assert.Equal(t, true, constants["g_bpf_traceparent_enabled"])
		})
	}
}

func TestTraceparentParsingCoversGlobalAndPerProcessSamplerTransitions(t *testing.T) {
	parentBased := &services.SamplerConfig{Name: services.SamplerParentBasedAlwaysOn}
	traceIDRatio := &services.SamplerConfig{Name: services.SamplerTraceIDRatio, Arg: "0.25"}
	rootOnly := &services.SamplerConfig{Name: services.SamplerAlwaysOff}

	for _, tt := range []struct {
		name      string
		configure func(*obi.Config)
		enabled   bool
	}{
		{
			name: "global parent based before process readiness",
			configure: func(cfg *obi.Config) {
				cfg.Traces.SamplerConfig = *parentBased
			},
			enabled: true,
		},
		{
			name: "global parent based to root-only process",
			configure: func(cfg *obi.Config) {
				cfg.Traces.SamplerConfig = *parentBased
				cfg.Discovery.Instrument = services.GlobDefinitionCriteria{{SamplerConfig: rootOnly}}
			},
			enabled: true,
		},
		{
			name: "root-only global to instrument process parent based",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Instrument = services.GlobDefinitionCriteria{{SamplerConfig: parentBased}}
			},
			enabled: true,
		},
		{
			name: "root-only global to legacy service process parent based",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Services = services.RegexDefinitionCriteria{{SamplerConfig: parentBased}}
			},
			enabled: true,
		},
		{
			name: "global trace ID ratio",
			configure: func(cfg *obi.Config) {
				cfg.Traces.SamplerConfig = *traceIDRatio
			},
			enabled: true,
		},
		{
			name: "root-only global to instrument process trace ID ratio",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Instrument = services.GlobDefinitionCriteria{{SamplerConfig: traceIDRatio}}
			},
			enabled: true,
		},
		{
			name: "root-only global to legacy service process trace ID ratio",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Services = services.RegexDefinitionCriteria{{SamplerConfig: traceIDRatio}}
			},
			enabled: true,
		},
		{
			name: "root-only samplers",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Instrument = services.GlobDefinitionCriteria{{SamplerConfig: rootOnly}}
			},
		},
		{
			name: "request header tracking",
			configure: func(cfg *obi.Config) {
				cfg.EBPF.TrackRequestHeaders = true
			},
			enabled: true,
		},
		{
			name: "context propagation",
			configure: func(cfg *obi.Config) {
				cfg.EBPF.ContextPropagation = config.ContextPropagationHeaders
			},
			enabled: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := traceparentParsingTestConfig()
			tt.configure(&cfg)

			constants := New(fakeServiceFilter{}, &cfg, nil).constants()

			captureValue := int32(0)
			if tt.enabled {
				captureValue = 1
			}
			assert.Equal(t, captureValue, constants["capture_header_buffer"])
			assert.Equal(t, tt.enabled, constants["g_bpf_traceparent_enabled"])
		})
	}
}

func traceparentParsingTestConfig() obi.Config {
	cfg := obi.DefaultConfig
	cfg.EBPF.TrackRequestHeaders = false
	cfg.EBPF.ContextPropagation = config.ContextPropagationDisabled
	cfg.Discovery = services.DiscoveryConfig{}
	cfg.Traces.SamplerConfig = services.SamplerConfig{Name: services.SamplerAlwaysOff}
	return cfg
}

func TestRawJVMEventLayoutsUseGeneratedBPFStructs(t *testing.T) {
	assert.Equal(t, 200, int(unsafe.Sizeof(BpfJvmMemPoolGcEvent{})))
}

func rawMemoryPoolPayload(t *testing.T, raw BpfJvmMemPoolGcEvent) []byte {
	t.Helper()

	return rawPayload(raw)
}

func rawPayload[T any](raw T) []byte {
	size := int(unsafe.Sizeof(raw))
	out := make([]byte, size)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), size))
	return out
}

func rawJVMString(value string) [jvmruntime.JVMRawStringLen]byte {
	var raw [jvmruntime.JVMRawStringLen]byte
	copy(raw[:], []byte(value))
	return raw
}

func readJVMTestBatch(t *testing.T, events <-chan []runtimemetrics.RuntimeMetricSnapshot) []runtimemetrics.RuntimeMetricSnapshot {
	t.Helper()

	select {
	case batch := <-events:
		return batch
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for JVM runtime events")
		return nil
	}
}

type fakeServiceFilter struct {
	current          map[uint32]map[app.PID]svc.Attrs
	currentPIDsCalls *int
}

type lifecycleServiceFilter struct {
	mu           sync.Mutex
	allowed      int
	blocked      int
	order        []string
	allowEntered chan struct{}
	releaseAllow chan struct{}
	blockEntered chan struct{}
}

type blockingCurrentPIDsFilter struct {
	fakeServiceFilter
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type fakeSamplerLifecycleManager struct {
	allowResults    []bool
	blockResults    []bool
	fallbackResults []bool
	blockResult     func(uint64) bool
	fallbackResult  func(uint64) bool
	allowStartTimes []uint64
	blockStartTimes []uint64
	fallbackStarts  []uint64
}

type genericRunCloser struct {
	mu     sync.Mutex
	closed int
}

type blockingGenericRunCloser struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	closed  int
}

type signalingLogHandler struct {
	message  string
	signaled chan struct{}
	once     sync.Once
}

func (*signalingLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *signalingLogHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Message == h.message {
		h.once.Do(func() { close(h.signaled) })
	}
	return nil
}

func (h *signalingLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *signalingLogHandler) WithGroup(string) slog.Handler { return h }

func (c *genericRunCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	return nil
}

func (c *genericRunCloser) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *blockingGenericRunCloser) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return nil
}

func (c *blockingGenericRunCloser) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (*fakeSamplerLifecycleManager) InstallGlobal() bool {
	return true
}

func (m *fakeSamplerLifecycleManager) AllowPIDForProcess(
	_ app.PID,
	_ uint32,
	startTime uint64,
	_ *services.CanonicalSampler,
	_ bool,
) bool {
	m.allowStartTimes = append(m.allowStartTimes, startTime)
	return nextSamplerLifecycleResult(&m.allowResults)
}

func (m *fakeSamplerLifecycleManager) BlockPIDForProcess(
	_ app.PID,
	_ uint32,
	startTime uint64,
) bool {
	m.blockStartTimes = append(m.blockStartTimes, startTime)
	if m.blockResult != nil {
		return m.blockResult(startTime)
	}
	return nextSamplerLifecycleResult(&m.blockResults)
}

func (m *fakeSamplerLifecycleManager) FallbackSafeForProcessIncarnation(
	_ app.PID,
	_ uint32,
	startTime uint64,
) bool {
	m.fallbackStarts = append(m.fallbackStarts, startTime)
	if m.fallbackResult != nil {
		return m.fallbackResult(startTime)
	}
	return nextSamplerLifecycleResult(&m.fallbackResults)
}

func nextSamplerLifecycleResult(results *[]bool) bool {
	if len(*results) == 0 {
		return true
	}
	result := (*results)[0]
	*results = (*results)[1:]
	return result
}

func (f *lifecycleServiceFilter) AllowPID(
	app.PID,
	uint32,
	*exec.FileInfo,
	ebpfcommon.PIDType,
) {
	if f.allowEntered != nil {
		close(f.allowEntered)
		<-f.releaseAllow
	}
	f.mu.Lock()
	f.allowed++
	f.order = append(f.order, "allow")
	f.mu.Unlock()
}

func (f *lifecycleServiceFilter) BlockPID(app.PID, uint32) {
	if f.blockEntered != nil {
		close(f.blockEntered)
	}
	f.mu.Lock()
	f.blocked++
	f.order = append(f.order, "block")
	f.mu.Unlock()
}

func (*lifecycleServiceFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool {
	return false
}

func (*lifecycleServiceFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

func (*lifecycleServiceFilter) CurrentPIDs(
	ebpfcommon.PIDType,
) map[uint32]map[app.PID]svc.Attrs {
	return nil
}

func (f *blockingCurrentPIDsFilter) CurrentPIDs(
	ebpfcommon.PIDType,
) map[uint32]map[app.PID]svc.Attrs {
	f.once.Do(func() { close(f.entered) })
	<-f.release
	return nil
}

func TestDelayedBlockDoesNotRemoveReplacementProcess(t *testing.T) {
	filter := &lifecycleServiceFilter{}
	tracer := &Tracer{
		pidsFilter:       filter,
		processStartTime: map[genericProcessKey]uint64{},
	}
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
		ino       = uint64(42)
	)
	oldFileInfo := exec.New(exec.Init{
		Pid: pid, Ns: ns, StartTime: startTime, Ino: ino,
	})
	newFileInfo := exec.New(exec.Init{
		Pid: pid, Ns: ns, StartTime: startTime, Ino: ino,
	})

	tracer.AllowPID(pid, ns, oldFileInfo)
	tracer.AllowPID(pid, ns, newFileInfo)
	tracer.BlockPIDForProcess(pid, ns, oldFileInfo)

	assert.Equal(t, 2, filter.allowed)
	assert.Zero(t, filter.blocked)
	assert.Equal(t, startTime, tracer.processStartTime[genericProcessKey{pid: pid, ns: ns}])
	assert.Same(t, newFileInfo, tracer.processFileInfo[genericProcessKey{pid: pid, ns: ns}])
}

func TestAllowAndBlockLifecycleIsSerialized(t *testing.T) {
	filter := &lifecycleServiceFilter{
		allowEntered: make(chan struct{}),
		releaseAllow: make(chan struct{}),
		blockEntered: make(chan struct{}),
	}
	tracer := &Tracer{
		pidsFilter:       filter,
		processStartTime: map[genericProcessKey]uint64{},
	}
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
	)
	fileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: startTime})

	allowDone := make(chan struct{})
	go func() {
		tracer.AllowPID(pid, ns, fileInfo)
		close(allowDone)
	}()
	<-filter.allowEntered

	blockDone := make(chan struct{})
	go func() {
		tracer.BlockPIDForProcess(pid, ns, fileInfo)
		close(blockDone)
	}()

	select {
	case <-filter.blockEntered:
		t.Fatal("BlockPIDForProcess entered the filter before AllowPID completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(filter.releaseAllow)
	<-allowDone
	<-blockDone

	filter.mu.Lock()
	defer filter.mu.Unlock()
	assert.Equal(t, []string{"allow", "block"}, filter.order)
	assert.NotContains(t, tracer.processStartTime, genericProcessKey{pid: pid, ns: ns})
}

func TestInitializePIDFilterSerializesLifecycleUpdates(t *testing.T) {
	release := make(chan struct{})
	filter := &blockingCurrentPIDsFilter{
		entered: make(chan struct{}),
		release: release,
	}
	cfg := obi.DefaultConfig
	tracer := New(filter, &cfg, nil)
	tracer.bpfObjects.ValidPids = new(ebpf.Map)

	done := make(chan struct{})
	go func() {
		tracer.initializePIDFilter()
		close(done)
	}()

	select {
	case <-filter.entered:
	case <-time.After(time.Second):
		t.Fatal("initial PID filter rebuild did not start")
	}
	assert.False(t, tracer.processMu.TryLock(),
		"startup PID filter rebuild must hold the lifecycle lock")

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("initial PID filter rebuild did not finish")
	}
	require.True(t, tracer.processMu.TryLock())
	tracer.processMu.Unlock()
}

func TestPIDFilterBlockFailureDefersSamplerCleanup(t *testing.T) {
	for _, tt := range []struct {
		name    string
		fail    func(*Tracer)
		recover func(*Tracer)
	}{
		{
			name: "valid PID rebuild",
			fail: func(tracer *Tracer) {
				tracer.bpfObjects.ValidPids = new(ebpf.Map)
			},
			recover: func(tracer *Tracer) {
				tracer.bpfObjects.ValidPids = nil
			},
		},
		{
			name: "PID cache invalidation",
			fail: func(tracer *Tracer) {
				tracer.bpfObjects.PidCache = new(ebpf.Map)
			},
			recover: func(tracer *Tracer) {
				tracer.bpfObjects.PidCache = nil
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const (
				pid       = app.PID(123)
				ns        = uint32(7)
				startTime = uint64(100)
			)
			key := genericProcessKey{pid: pid, ns: ns}
			fileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: startTime})
			retryKey := samplerCleanupRetryKey{
				process: key, startTime: startTime, fileInfo: fileInfo,
			}
			filter := &lifecycleServiceFilter{}
			sampler := &fakeSamplerLifecycleManager{}
			cfg := obi.DefaultConfig
			tracer := New(filter, &cfg, nil)
			tracer.samplerManager = sampler
			tracer.processStartTime[key] = startTime
			tracer.processFileInfo[key] = fileInfo
			tt.fail(tracer)

			tracer.BlockPIDForProcess(pid, ns, fileInfo)

			retry, pending := tracer.samplerCleanupRetries[retryKey]
			require.True(t, pending)
			assert.True(t, retry.pidFilterBlockPending)
			assert.Empty(t, sampler.blockStartTimes,
				"sampler cleanup must wait until BPF admission is revoked")

			tt.recover(tracer)
			tracer.retrySamplerCleanups()

			assert.NotContains(t, tracer.samplerCleanupRetries, retryKey)
			assert.Equal(t, []uint64{startTime}, sampler.blockStartTimes)
			assert.Equal(t, []uint64{startTime}, sampler.fallbackStarts)
			assert.Equal(t, 1, filter.blocked)
		})
	}
}

func TestPIDFilterBlockRetryDoesNotBlockReplacementProcess(t *testing.T) {
	const (
		pid          = app.PID(123)
		ns           = uint32(7)
		oldStartTime = uint64(100)
		newStartTime = uint64(200)
	)
	key := genericProcessKey{pid: pid, ns: ns}
	oldFileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: oldStartTime})
	newFileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: newStartTime})
	oldRetryKey := samplerCleanupRetryKey{
		process: key, startTime: oldStartTime, fileInfo: oldFileInfo,
	}
	filter := &lifecycleServiceFilter{}
	sampler := &fakeSamplerLifecycleManager{}
	cfg := obi.DefaultConfig
	tracer := New(filter, &cfg, nil)
	tracer.samplerManager = sampler
	tracer.processStartTime[key] = oldStartTime
	tracer.processFileInfo[key] = oldFileInfo
	tracer.bpfObjects.ValidPids = new(ebpf.Map)

	tracer.BlockPIDForProcess(pid, ns, oldFileInfo)
	require.True(t, tracer.samplerCleanupRetries[oldRetryKey].pidFilterBlockPending)

	tracer.bpfObjects.ValidPids = nil
	require.True(t, tracer.AllowPIDForProcess(pid, ns, newFileInfo))
	tracer.retrySamplerCleanups()

	assert.NotContains(t, tracer.samplerCleanupRetries, oldRetryKey)
	assert.Equal(t, 1, filter.blocked)
	assert.Equal(t, 1, filter.allowed)
	assert.Equal(t, newStartTime, tracer.processStartTime[key])
	assert.Same(t, newFileInfo, tracer.processFileInfo[key])
	assert.Equal(t, []uint64{oldStartTime}, sampler.blockStartTimes)
	assert.Equal(t, []uint64{oldStartTime}, sampler.fallbackStarts)
}

func TestSamplerCleanupRetriesOriginalProcessUntilFallbackSafe(t *testing.T) {
	filter := &lifecycleServiceFilter{}
	sampler := &fakeSamplerLifecycleManager{
		blockResults:    []bool{false, true, true},
		fallbackResults: []bool{false, true},
	}
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
	)
	key := genericProcessKey{pid: pid, ns: ns}
	fileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: startTime})
	retryKey := samplerCleanupRetryKey{
		process: key, startTime: startTime, fileInfo: fileInfo,
	}
	tracer := &Tracer{
		pidsFilter:       filter,
		processStartTime: map[genericProcessKey]uint64{key: startTime},
		processFileInfo:  map[genericProcessKey]*exec.FileInfo{key: fileInfo},
		samplerManager:   sampler,
	}

	tracer.BlockPIDForProcess(pid, ns, fileInfo)

	assert.Equal(t, 1, filter.blocked)
	assert.NotContains(t, tracer.processStartTime, key)
	assert.NotContains(t, tracer.processFileInfo, key)
	assert.Contains(t, tracer.samplerCleanupRetries, retryKey)

	tracer.retrySamplerCleanups()
	assert.Contains(t, tracer.samplerCleanupRetries, retryKey)

	tracer.retrySamplerCleanups()
	assert.NotContains(t, tracer.samplerCleanupRetries, retryKey)
	assert.Equal(t, []uint64{startTime, startTime, startTime}, sampler.blockStartTimes)
	assert.Equal(t, []uint64{startTime, startTime}, sampler.fallbackStarts)
}

func TestSuccessfulReplacementAdmissionKeepsOlderSamplerCleanupRetry(t *testing.T) {
	filter := &lifecycleServiceFilter{}
	sampler := &fakeSamplerLifecycleManager{
		allowResults: []bool{true},
		blockResults: []bool{false},
	}
	const (
		pid          = app.PID(123)
		ns           = uint32(7)
		oldStartTime = uint64(100)
		newStartTime = uint64(200)
	)
	key := genericProcessKey{pid: pid, ns: ns}
	oldFileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: oldStartTime})
	newFileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: newStartTime})
	oldRetryKey := samplerCleanupRetryKey{
		process: key, startTime: oldStartTime, fileInfo: oldFileInfo,
	}
	tracer := &Tracer{
		pidsFilter:       filter,
		processStartTime: map[genericProcessKey]uint64{key: oldStartTime},
		processFileInfo:  map[genericProcessKey]*exec.FileInfo{key: oldFileInfo},
		samplerManager:   sampler,
	}

	tracer.BlockPIDForProcess(pid, ns, oldFileInfo)
	require.Contains(t, tracer.samplerCleanupRetries, oldRetryKey)
	require.True(t, tracer.AllowPIDForProcess(pid, ns, newFileInfo))
	require.Contains(t, tracer.samplerCleanupRetries, oldRetryKey)

	tracer.retrySamplerCleanups()
	assert.Empty(t, tracer.samplerCleanupRetries)
	assert.Equal(t, []uint64{oldStartTime, oldStartTime}, sampler.blockStartTimes)
	assert.Equal(t, []uint64{newStartTime}, sampler.allowStartTimes)
	assert.Equal(t, newStartTime, tracer.processStartTime[key])
	assert.Same(t, newFileInfo, tracer.processFileInfo[key])
}

func TestSamplerCleanupRetryNeverAdmitsProcess(t *testing.T) {
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
		ino       = uint64(42)
	)
	filter := &lifecycleServiceFilter{}
	sampler := &fakeSamplerLifecycleManager{
		allowResults:    []bool{false},
		blockResults:    []bool{false, true},
		fallbackResults: []bool{false, true},
	}
	fileInfo := exec.New(exec.Init{
		Pid: pid, Ns: ns, StartTime: startTime, Dev: 5, Ino: ino,
	})
	tracer := &Tracer{
		pidsFilter:       filter,
		processStartTime: map[genericProcessKey]uint64{},
		processFileInfo:  map[genericProcessKey]*exec.FileInfo{},
		samplerManager:   sampler,
	}

	require.False(t, tracer.AllowPIDForProcess(pid, ns, fileInfo))
	assert.True(t, tracer.PIDAdmissionRetryPending(pid, ns, fileInfo))
	tracer.retrySamplerCleanups()

	assert.True(t, tracer.PIDAdmissionRetryPending(pid, ns, fileInfo))
	assert.Zero(t, filter.allowed)
	assert.Empty(t, tracer.processStartTime)
	assert.Empty(t, tracer.processFileInfo)
	assert.Equal(t, []uint64{startTime}, sampler.allowStartTimes)
	assert.Equal(t, []uint64{startTime, startTime}, sampler.blockStartTimes)

	tracer.CancelPIDAdmissionRetry(pid, ns, fileInfo)
	assert.False(t, tracer.PIDAdmissionRetryPending(pid, ns, fileInfo))
	assert.True(t, tracer.ResourceTeardownReady())
}

func TestSamplerCleanupRetriesKeepProcessGenerationsSeparate(t *testing.T) {
	const (
		pid          = app.PID(123)
		ns           = uint32(7)
		oldStartTime = uint64(100)
		newStartTime = uint64(200)
	)
	cleanupSafe := map[uint64]bool{}
	filter := &lifecycleServiceFilter{}
	sampler := &fakeSamplerLifecycleManager{
		allowResults: []bool{false, false},
		blockResult: func(startTime uint64) bool {
			return cleanupSafe[startTime]
		},
		fallbackResult: func(startTime uint64) bool {
			return cleanupSafe[startTime]
		},
	}
	process := genericProcessKey{pid: pid, ns: ns}
	oldFileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: oldStartTime})
	newFileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: newStartTime, Ino: 42})
	oldRetry := samplerCleanupRetryKey{
		process: process, startTime: oldStartTime, fileInfo: oldFileInfo,
	}
	newRetry := samplerCleanupRetryKey{
		process: process, startTime: newStartTime, ino: 42,
		fileInfo: newFileInfo,
	}
	tracer := &Tracer{
		pidsFilter:       filter,
		processStartTime: map[genericProcessKey]uint64{},
		processFileInfo:  map[genericProcessKey]*exec.FileInfo{},
		samplerManager:   sampler,
	}

	require.False(t, tracer.AllowPIDForProcess(pid, ns, oldFileInfo))
	require.False(t, tracer.AllowPIDForProcess(pid, ns, newFileInfo))
	require.Len(t, tracer.samplerCleanupRetries, 2)
	assert.Zero(t, tracer.samplerCleanupRetries[oldRetry].ino)
	assert.Equal(t, newFileInfo.Ino(), tracer.samplerCleanupRetries[newRetry].ino)

	cleanupSafe[newStartTime] = true
	tracer.retrySamplerCleanups()
	assert.Contains(t, tracer.samplerCleanupRetries, oldRetry)
	assert.Contains(t, tracer.samplerCleanupRetries, newRetry)
	assert.True(t, tracer.samplerCleanupRetries[newRetry].cleanupComplete)
	assert.Zero(t, filter.allowed)
	assert.Empty(t, tracer.processStartTime)
	assert.Empty(t, tracer.processFileInfo)
	tracer.CancelPIDAdmissionRetry(pid, ns, newFileInfo)
	assert.Contains(t, tracer.samplerCleanupRetries, oldRetry)
	assert.NotContains(t, tracer.samplerCleanupRetries, newRetry)

	cleanupSafe[oldStartTime] = true
	tracer.retrySamplerCleanups()
	assert.Contains(t, tracer.samplerCleanupRetries, oldRetry)
	tracer.CancelPIDAdmissionRetry(pid, ns, oldFileInfo)
	assert.Empty(t, tracer.samplerCleanupRetries)
	assert.Zero(t, filter.allowed)
}

func TestSamplerCleanupDebtSeparatesSameTickSameInodeFileInfos(t *testing.T) {
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
	)
	sampler := &fakeSamplerLifecycleManager{
		allowResults:    []bool{false, false},
		blockResults:    []bool{false, false},
		fallbackResults: []bool{false, false},
	}
	first := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: startTime, Ino: 41})
	second := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: startTime, Ino: 41})
	tracer := &Tracer{
		pidsFilter:       &lifecycleServiceFilter{},
		processStartTime: map[genericProcessKey]uint64{},
		processFileInfo:  map[genericProcessKey]*exec.FileInfo{},
		samplerManager:   sampler,
	}

	require.False(t, tracer.AllowPIDForProcess(pid, ns, first))
	require.False(t, tracer.AllowPIDForProcess(pid, ns, second))
	require.Len(t, tracer.samplerCleanupRetries, 2)
	assert.True(t, tracer.PIDAdmissionRetryPending(pid, ns, first))
	assert.True(t, tracer.PIDAdmissionRetryPending(pid, ns, second))

	tracer.CancelPIDAdmissionRetry(pid, ns, first)
	assert.False(t, tracer.PIDAdmissionRetryPending(pid, ns, first))
	assert.True(t, tracer.PIDAdmissionRetryPending(pid, ns, second))
}

func TestSamplerCleanupDebtBlocksUnlinkAndTeardownByInode(t *testing.T) {
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
		ino       = uint64(42)
	)
	cleanupSafe := false
	sampler := &fakeSamplerLifecycleManager{
		allowResults: []bool{false},
		blockResult: func(uint64) bool {
			return cleanupSafe
		},
		fallbackResult: func(uint64) bool {
			return cleanupSafe
		},
	}
	fileInfo := exec.New(exec.Init{
		Pid: pid, Ns: ns, StartTime: startTime, Ino: ino,
	})
	tracer := &Tracer{
		pidsFilter:       &lifecycleServiceFilter{},
		processStartTime: map[genericProcessKey]uint64{},
		processFileInfo:  map[genericProcessKey]*exec.FileInfo{},
		samplerManager:   sampler,
	}

	require.False(t, tracer.AllowPIDForProcess(pid, ns, fileInfo))
	assert.False(t, tracer.ExecutableUnlinkReady(fileInfo))
	assert.False(t, tracer.ResourceTeardownReady())
	assert.True(t, tracer.ExecutableUnlinkReady(exec.New(exec.Init{Ino: ino + 1})))
	assert.True(t, tracer.ExecutableUnlinkReady(exec.New(exec.Init{Dev: 6, Ino: ino})))

	tracer.CancelPIDAdmissionRetry(pid, ns, fileInfo)
	assert.False(t, tracer.PIDAdmissionRetryPending(pid, ns, fileInfo))
	assert.False(t, tracer.ExecutableUnlinkReady(fileInfo))
	assert.False(t, tracer.ResourceTeardownReady())

	cleanupSafe = true
	tracer.retrySamplerCleanups()
	assert.True(t, tracer.ExecutableUnlinkReady(fileInfo))
	assert.True(t, tracer.ResourceTeardownReady())
}

func TestRunClosesGenericResourcesWhenCleanupIsSafe(t *testing.T) {
	cfg := obi.DefaultConfig
	tracer := New(&lifecycleServiceFilter{}, &cfg, nil)
	closer := &genericRunCloser{}
	tracer.AddCloser(closer)

	eventContext := ebpfcommon.NewEBPFEventContext()
	ebpfcommon.SharedRingbuf[request.Span](
		eventContext,
		&tracer.cfg.EBPF,
		nil,
		nil,
		nil,
		tracer.log,
		nil,
	)
	runCtx, cancel := context.WithCancel(t.Context())
	cancel()

	tracer.Run(runCtx, eventContext, nil)

	assert.Equal(t, 1, closer.closeCount())
	assert.True(t, tracer.ResourceTeardownReady())
}

func TestRunRetainsGenericResourcesUntilCleanupDebtClears(t *testing.T) {
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
		ino       = uint64(42)
	)
	cleanupSafe := make(chan struct{})
	isCleanupSafe := func() bool {
		select {
		case <-cleanupSafe:
			return true
		default:
			return false
		}
	}
	sampler := &fakeSamplerLifecycleManager{
		blockResult: func(uint64) bool {
			return isCleanupSafe()
		},
		fallbackResult: func(uint64) bool {
			return isCleanupSafe()
		},
	}
	fileInfo := exec.New(exec.Init{
		Pid: pid, Ns: ns, StartTime: startTime, Ino: ino,
	})
	retryKey := samplerCleanupRetryKey{
		process:   genericProcessKey{pid: pid, ns: ns},
		startTime: startTime,
		ino:       ino,
		fileInfo:  fileInfo,
	}
	cfg := obi.DefaultConfig
	tracer := New(&lifecycleServiceFilter{}, &cfg, nil)
	tracer.samplerManager = sampler
	tracer.samplerCleanupRetries[retryKey] = samplerCleanupRetry{ino: ino}
	closer := &genericRunCloser{}
	tracer.AddCloser(closer)

	eventContext := ebpfcommon.NewEBPFEventContext()
	ebpfcommon.SharedRingbuf[request.Span](
		eventContext,
		&tracer.cfg.EBPF,
		nil,
		nil,
		nil,
		tracer.log,
		nil,
	)
	runCtx, cancel := context.WithCancel(t.Context())
	cancel()

	tracer.Run(runCtx, eventContext, nil)

	assert.Zero(t, closer.closeCount())
	assert.False(t, tracer.ResourceTeardownReady())

	cleanupDone := make(chan struct{})
	go func() {
		tracer.WaitForResourceTeardown()
		close(cleanupDone)
	}()
	select {
	case <-cleanupDone:
		t.Fatal("resource cleanup completed while sampler debt was unsafe")
	case <-time.After(20 * time.Millisecond):
	}
	close(cleanupSafe)
	select {
	case <-cleanupDone:
	case <-time.After(2 * time.Second):
		t.Fatal("post-cancellation cleanup owner did not release resources")
	}

	assert.Equal(t, 1, closer.closeCount())
	assert.True(t, tracer.ResourceTeardownReady())
}

func TestShutdownWaitsForConcurrentResourceClose(t *testing.T) {
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
	)
	fileInfo := exec.New(exec.Init{Pid: pid, Ns: ns, StartTime: startTime})
	retryKey := samplerCleanupRetryKey{
		process:   genericProcessKey{pid: pid, ns: ns},
		startTime: startTime,
		fileInfo:  fileInfo,
	}
	closer := &blockingGenericRunCloser{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	tracer := &Tracer{
		runResourcesShutdown: true,
		runResourcesDone:     make(chan struct{}),
		samplerManager:       &fakeSamplerLifecycleManager{},
		samplerCleanupRetries: map[samplerCleanupRetryKey]samplerCleanupRetry{
			retryKey: {},
		},
		closers: []io.Closer{closer},
	}

	retryDone := make(chan struct{})
	go func() {
		tracer.retrySamplerCleanups()
		close(retryDone)
	}()
	select {
	case <-closer.started:
	case <-time.After(time.Second):
		t.Fatal("cleanup retry did not start closing resources")
	}

	shutdownDone := make(chan struct{})
	go func() {
		tracer.shutdownRunResources()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned while resource closure was in progress")
	case <-time.After(20 * time.Millisecond):
	}

	close(closer.release)
	select {
	case <-retryDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup retry did not finish")
	}
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not observe completed resource closure")
	}

	assert.Equal(t, 1, closer.closeCount())
	assert.True(t, tracer.ResourceTeardownReady())
}

func TestProcessTracerWaitsForGenericPostCancellationCleanup(t *testing.T) {
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
		ino       = uint64(42)
	)
	cleanupSafe := make(chan struct{})
	isCleanupSafe := func() bool {
		select {
		case <-cleanupSafe:
			return true
		default:
			return false
		}
	}
	sampler := &fakeSamplerLifecycleManager{
		allowResults: []bool{true},
		blockResult: func(uint64) bool {
			return isCleanupSafe()
		},
		fallbackResult: func(uint64) bool {
			return isCleanupSafe()
		},
	}
	fileInfo := exec.New(exec.Init{
		Pid: pid, Ns: ns, StartTime: startTime, Ino: ino,
	})
	cfg := obi.DefaultConfig
	tracer := New(&lifecycleServiceFilter{}, &cfg, nil)
	tracer.samplerManager = sampler
	require.True(t, tracer.AllowPIDForProcess(pid, ns, fileInfo))
	tracer.BlockPIDForProcess(pid, ns, fileInfo)
	require.False(t, tracer.ResourceTeardownReady())
	closer := &genericRunCloser{}
	tracer.AddCloser(closer)

	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.EBPFMaps["shared"] = nil
	ebpfcommon.SharedRingbuf[request.Span](
		eventContext,
		&tracer.cfg.EBPF,
		nil,
		nil,
		nil,
		tracer.log,
		nil,
	)
	processTracer := obiebpf.NewProcessTracer(
		obiebpf.Generic,
		[]obiebpf.Tracer{tracer},
		&cfg,
		nil,
	)
	runCtx, cancel := context.WithCancel(t.Context())
	processDone := make(chan struct{})
	go func() {
		processTracer.Run(runCtx, eventContext, nil)
		close(processDone)
	}()
	cancel()

	select {
	case <-processDone:
		t.Fatal("process tracer returned while generic cleanup was unsafe")
	case <-time.After(20 * time.Millisecond):
	}
	assert.Zero(t, closer.closeCount())
	assert.False(t, eventContext.ResourcesRetained())

	close(cleanupSafe)
	select {
	case <-processDone:
	case <-time.After(2 * time.Second):
		t.Fatal("process tracer did not finish after generic cleanup became safe")
	}

	assert.Equal(t, 1, closer.closeCount())
	assert.True(t, tracer.ResourceTeardownReady())
	assert.False(t, eventContext.ResourcesRetained())
	require.Len(t, eventContext.EBPFMaps, 1)
	obiebpf.ShutdownSharedMaps(eventContext)
	assert.Empty(t, eventContext.EBPFMaps)
}

func TestRunKeepsResourcesAfterLiveContextReaderFailure(t *testing.T) {
	const (
		pid       = app.PID(123)
		ns        = uint32(7)
		startTime = uint64(100)
		ino       = uint64(42)
	)
	fileInfo := exec.New(exec.Init{
		Pid: pid, Ns: ns, StartTime: startTime, Ino: ino,
	})
	cfg := obi.DefaultConfig
	tracer := New(&lifecycleServiceFilter{}, &cfg, nil)
	tracer.samplerManager = &fakeSamplerLifecycleManager{
		allowResults: []bool{true},
	}
	readerFailed := make(chan struct{})
	tracer.log = slog.New(&signalingLogHandler{
		message:  "creating ring buffer reader. Exiting",
		signaled: readerFailed,
	})
	tracer.bpfObjects.Events = &ebpf.Map{}
	closer := &genericRunCloser{}
	tracer.AddCloser(closer)

	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.EBPFMaps["shared"] = nil
	processTracer := obiebpf.NewProcessTracer(
		obiebpf.Generic,
		[]obiebpf.Tracer{tracer},
		&cfg,
		nil,
	)
	runCtx, cancel := context.WithCancel(t.Context())
	processDone := make(chan struct{})
	go func() {
		processTracer.Run(runCtx, eventContext, nil)
		close(processDone)
	}()

	select {
	case <-readerFailed:
	case <-time.After(time.Second):
		t.Fatal("shared ring buffer reader creation did not fail")
	}
	// The zero-value map forced the production reader failure. Remove it only
	// after the failure log synchronizes with that completed read attempt so
	// generated BpfObjects.Close does not dereference its intentionally nil FD.
	tracer.bpfObjects.Events = nil
	select {
	case <-processDone:
		t.Fatal("process tracer returned while its context was still live")
	case <-time.After(20 * time.Millisecond):
	}
	assert.Zero(t, closer.closeCount())
	assert.True(t, tracer.ResourceTeardownReady())

	require.True(t, processTracer.AllowPID(pid, ns, fileInfo))
	processTracer.BlockPIDForProcess(pid, ns, fileInfo)
	assert.False(t, processTracer.PIDAdmissionRetryPending(pid, ns, fileInfo))
	assert.True(t, tracer.ResourceTeardownReady())
	assert.Zero(t, closer.closeCount())

	cancel()
	select {
	case <-processDone:
	case <-time.After(time.Second):
		t.Fatal("process tracer did not finish after cancellation")
	}

	assert.Equal(t, 1, closer.closeCount())
	assert.True(t, tracer.ResourceTeardownReady())
	assert.False(t, eventContext.ResourcesRetained())
	require.Len(t, eventContext.EBPFMaps, 1)
	obiebpf.ShutdownSharedMaps(eventContext)
	assert.Empty(t, eventContext.EBPFMaps)
}

func (f fakeServiceFilter) AllowPID(app.PID, uint32, *exec.FileInfo, ebpfcommon.PIDType) {}
func (f fakeServiceFilter) BlockPID(app.PID, uint32)                                     {}
func (f fakeServiceFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool            { return false }

func (f fakeServiceFilter) Filter(inputSpans []request.Span) []request.Span { return inputSpans }

func (f fakeServiceFilter) CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs {
	if f.currentPIDsCalls != nil {
		(*f.currentPIDsCalls)++
	}
	return f.current
}
