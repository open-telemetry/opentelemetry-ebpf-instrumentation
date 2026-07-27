// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher

import (
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	testPIDOTelService  uint32 = 33
	testPIDNonOTel      uint32 = 7
	testPIDFlagFlip     uint32 = 55
	testPIDDisabledGate uint32 = 42
	testPIDUntracked    uint32 = 99
)

func applyTestTraceContext(m map[string]any, includeSpan bool) {
	applyTraceContext(m, obi.DefaultConfig.EBPF.LogEnricher.FieldNames, testTraceID, testSpanID, includeSpan)
}

func newTestTracer(t *testing.T, exclude bool) *Tracer {
	t.Helper()
	return &Tracer{
		log: slog.With("component", "logenricher-test"),
		cfg: &obi.Config{
			Discovery: services.DiscoveryConfig{
				ExcludeOTelInstrumentedServices: exclude,
			},
		},
		pids:        map[uint64][]uint64{},
		pidServices: map[uint32]*exec.FileInfo{},
		pidsMU:      sync.Mutex{},
	}
}

func TestBlockPIDClearsNamespacedPIDCache(t *testing.T) {
	tr := newTestTracer(t, false)

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("removing memlock failed: %v", err)
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "le_pids_test",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("ebpf map create failed: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("close eBPF map: %v", err)
		}
	})
	tr.bpfObjects.LogEnricherPids = m

	const (
		ns    = 1
		pid   = 12345
		nsPID = 2345
	)

	pk := tr.pidKey(ns, pid)
	nsPk := tr.pidKey(ns, nsPID)
	tr.pids[pk] = []uint64{nsPk}

	require.NoError(t, m.Put(pk, uint8(1)))
	require.NoError(t, m.Put(nsPk, uint8(1)))

	tr.BlockPID(pid, ns)

	_, ok := tr.pids[pk]
	assert.False(t, ok)

	var value uint8
	require.ErrorIs(t, m.Lookup(pk, &value), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, m.Lookup(nsPk, &value), ebpf.ErrKeyNotExist)
}

func TestPIDOpsWithoutLoadedObjectsDoNotPanic(t *testing.T) {
	tr := newTestTracer(t, false)

	require.Error(t, tr.addPID(tr.pidKey(1, 42)))
	require.Error(t, tr.removePID(tr.pidKey(1, 42)))
}

func TestHandleWithoutTraceContextPreservesPlainText(t *testing.T) {
	file, err := os.CreateTemp("/tmp", "obi-log-enricher-")
	require.NoError(t, err)
	path := file.Name()
	require.NoError(t, file.Close())
	t.Cleanup(func() { _ = os.Remove(path) })
	require.Less(t, len(path), len(BpfLogEventT{}.FilePath))

	cfg := obi.DefaultConfig
	tr := newTestTracer(t, false)
	tr.cfg = &cfg
	tr.formatter = newLogFormatter(cfg.EBPF.LogEnricher)
	tr.fdCache = expirable.NewLRU[string, *os.File](1, func(_ string, file *os.File) {
		_ = file.Close()
	}, time.Minute)
	t.Cleanup(tr.fdCache.Purge)

	event := LogEvent{logLine: "request failed\n"}
	copy(event.orig.FilePath[:], path)

	tr.handle(event)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, event.logLine, string(got))
}

func TestShouldOmitSpanID_FeatureDisabled(t *testing.T) {
	tr := newTestTracer(t, false)

	fi := exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "scoring-engine"}}})
	fi.EnsureExportsOTelTraces()
	tr.pidServices[testPIDDisabledGate] = fi

	assert.False(t, tr.shouldOmitSpanID(testPIDDisabledGate),
		"feature gate off: must not omit span_id even for OTel-exporting services")
}

func TestShouldOmitSpanID_UnknownPID(t *testing.T) {
	tr := newTestTracer(t, true)

	assert.False(t, tr.shouldOmitSpanID(testPIDUntracked),
		"unknown pid: fail-open, include span_id")
}

func TestShouldOmitSpanID_NonOTelService(t *testing.T) {
	tr := newTestTracer(t, true)

	tr.pidServices[testPIDNonOTel] = exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "regular"}}})

	assert.False(t, tr.shouldOmitSpanID(testPIDNonOTel),
		"non-OTel-exporting service: include span_id")
}

func TestShouldOmitSpanID_OTelService(t *testing.T) {
	tr := newTestTracer(t, true)

	fi := exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "scoring-engine"}}})
	fi.EnsureExportsOTelTraces()
	tr.pidServices[testPIDOTelService] = fi

	assert.True(t, tr.shouldOmitSpanID(testPIDOTelService),
		"OTel-exporting service with feature gate on: omit span_id")
}

func TestShouldOmitSpanID_ReflectsFlagFlip(t *testing.T) {
	tr := newTestTracer(t, true)

	fi := exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "scoring-engine"}}})
	tr.pidServices[testPIDFlagFlip] = fi

	assert.False(t, tr.shouldOmitSpanID(testPIDFlagFlip),
		"before flag flip: include span_id")

	fi.EnsureExportsOTelTraces()

	assert.True(t, tr.shouldOmitSpanID(testPIDFlagFlip),
		"after flag flip via shared pointer: omit span_id")
}

const (
	sdkTraceID = "ffeeddccbbaa99887766554433221100"
	sdkSpanID  = "ffeeddccbbaa9988"
)

func TestApplyTraceContext_IncludeSpan(t *testing.T) {
	m := map[string]any{"message": "hello"}

	applyTestTraceContext(m, true)

	assert.Equal(t, testTraceID, m["trace_id"])
	assert.Equal(t, testSpanID, m["span_id"])
}

func TestApplyTraceContext_IncludeSpan_PreservesExisting(t *testing.T) {
	m := map[string]any{"trace_id": sdkTraceID, "span_id": sdkSpanID}

	applyTestTraceContext(m, true)

	assert.Equal(t, sdkTraceID, m["trace_id"], "existing trace_id is preserved")
	assert.Equal(t, sdkSpanID, m["span_id"], "existing span_id is preserved")
}

func TestApplyTraceContext_IncludeSpan_FillsMissingSpanID(t *testing.T) {
	m := map[string]any{"trace_id": sdkTraceID}

	applyTestTraceContext(m, true)

	assert.Equal(t, sdkTraceID, m["trace_id"], "existing trace_id is preserved")
	assert.Equal(t, testSpanID, m["span_id"], "missing span_id is filled")
}

func TestApplyTraceContext_OTelInstrumented_FillsMissingTraceID(t *testing.T) {
	m := map[string]any{"message": "hello"}

	applyTestTraceContext(m, false)

	assert.Equal(t, testTraceID, m["trace_id"])
	_, hasSpan := m["span_id"]
	assert.False(t, hasSpan, "OTel-instrumented: must not inject span_id")
}

func TestApplyTraceContext_OTelInstrumented_PreservesSDKTraceID(t *testing.T) {
	m := map[string]any{"trace_id": sdkTraceID, "span_id": sdkSpanID}

	applyTestTraceContext(m, false)

	assert.Equal(t, sdkTraceID, m["trace_id"], "SDK's trace_id is preserved")
	assert.Equal(t, sdkSpanID, m["span_id"], "SDK's span_id is preserved")
}

func TestApplyTraceContext_OTelInstrumented_FillsTraceIDOnlyWhenSpanIDPresent(t *testing.T) {
	m := map[string]any{"span_id": sdkSpanID}

	applyTestTraceContext(m, false)

	assert.Equal(t, testTraceID, m["trace_id"], "OBI fills missing trace_id")
	assert.Equal(t, sdkSpanID, m["span_id"], "SDK's span_id stays untouched")
}
