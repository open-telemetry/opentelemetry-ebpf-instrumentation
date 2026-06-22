// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gotracer

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type noopServiceFilter struct{}

func (noopServiceFilter) AllowPID(app.PID, uint32, *exec.FileInfo, ebpfcommon.PIDType) {}
func (noopServiceFilter) BlockPID(app.PID, uint32)                                     {}
func (noopServiceFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool            { return false }
func (noopServiceFilter) Filter(spans []request.Span) []request.Span                   { return spans }
func (noopServiceFilter) CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs {
	return nil
}

func testTracer(t *testing.T, cfg *obi.Config) *Tracer {
	t.Helper()
	return New(noopServiceFilter{}, cfg, nil, msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot]())
}

func TestTracer_Constants(t *testing.T) {
	tests := []struct {
		name                        string
		contextPropagation          string
		trackRequestHeaders         bool
		headerPropagationMustBeOff  bool
		expectedTraceparentEnabled  bool
		expectedCaptureHeaderBuffer int32
	}{
		{
			name:                        "disabled",
			contextPropagation:          "disabled",
			headerPropagationMustBeOff:  true,
			expectedTraceparentEnabled:  false,
			expectedCaptureHeaderBuffer: 0,
		},
		{
			name:                        "headers",
			contextPropagation:          "headers",
			expectedTraceparentEnabled:  true,
			expectedCaptureHeaderBuffer: 1,
		},
		{
			name:                        "tcp only",
			contextPropagation:          "tcp",
			headerPropagationMustBeOff:  true,
			expectedTraceparentEnabled:  true,
			expectedCaptureHeaderBuffer: 1,
		},
		{
			name:                        "all",
			contextPropagation:          "all",
			expectedTraceparentEnabled:  true,
			expectedCaptureHeaderBuffer: 1,
		},
		{
			name:                        "disabled with track request headers",
			contextPropagation:          "disabled",
			trackRequestHeaders:         true,
			headerPropagationMustBeOff:  true,
			expectedTraceparentEnabled:  true,
			expectedCaptureHeaderBuffer: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &obi.Config{
				EBPF: config.EBPFTracer{
					MaxTransactionTime:  10 * time.Second,
					TrackRequestHeaders: tt.trackRequestHeaders,
				},
			}
			err := cfg.EBPF.ContextPropagation.UnmarshalText([]byte(tt.contextPropagation))
			require.NoError(t, err)

			tracer := testTracer(t, cfg)
			bundles, err := tracer.LoadSpecs()
			require.NoError(t, err)
			require.Len(t, bundles, 1)

			c := bundles[0].Constants

			headerPropagation, ok := c["g_bpf_header_propagation"]
			require.True(t, ok, "g_bpf_header_propagation should be present")
			assert.Equal(t, tracer.headerPropagationEnabled(), headerPropagation)
			if tt.headerPropagationMustBeOff {
				assert.False(t, headerPropagation.(bool))
			}

			traceparentEnabled, ok := c["g_bpf_traceparent_enabled"]
			require.True(t, ok, "g_bpf_traceparent_enabled should be present")
			assert.Equal(t, tt.expectedTraceparentEnabled, traceparentEnabled)

			captureHeaderBuffer, ok := c["capture_header_buffer"]
			require.True(t, ok, "capture_header_buffer should be present")
			assert.Equal(t, tt.expectedCaptureHeaderBuffer, captureHeaderBuffer)
		})
	}
}

func TestTracer_HeaderPropagationProbes(t *testing.T) {
	propagationProbeSymbols := []string{
		"net/http.Header.writeSubset",
		"golang.org/x/net/http2.(*Framer).WriteHeaders",
		"net/http.(*http2Framer).WriteHeaders",
	}

	tests := []struct {
		name               string
		contextPropagation string
		expectProbes       bool
	}{
		{
			name:               "disabled",
			contextPropagation: "disabled",
			expectProbes:       false,
		},
		{
			name:               "tcp only",
			contextPropagation: "tcp",
			expectProbes:       false,
		},
		{
			name:               "headers",
			contextPropagation: "headers",
			expectProbes:       true,
		},
		{
			name:               "all",
			contextPropagation: "all",
			expectProbes:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &obi.Config{
				Discovery: services.DiscoveryConfig{},
				EBPF: config.EBPFTracer{
					MaxTransactionTime: 10 * time.Second,
				},
			}
			err := cfg.EBPF.ContextPropagation.UnmarshalText([]byte(tt.contextPropagation))
			require.NoError(t, err)

			tracer := testTracer(t, cfg)
			probes := tracer.GoProbes()

			for _, symbol := range propagationProbeSymbols {
				_, found := probes[symbol]
				if tt.expectProbes && tracer.headerPropagationEnabled() {
					assert.True(t, found, "expected propagation probe %q to be registered", symbol)
				} else {
					assert.False(t, found, "expected propagation probe %q to be absent", symbol)
				}
			}

			// gRPC instrumentation probes must remain registered regardless of propagation mode.
			_, found := probes["google.golang.org/grpc.(*ClientConn).Invoke"]
			assert.True(t, found, "gRPC client probe should always be registered")
		})
	}
}

func TestGoChannelLinkProbesRequireChannelOffsets(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		goChannelOffsetsByIno: map[uint64]bool{},
	}

	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(
		exec.New(exec.Init{Ino: 1}),
		&goexec.Offsets{Field: goexec.FieldOffsets{
			goexec.HchanDataqsizPos: uint64(8),
			goexec.HchanSendxPos:    uint64(48),
		}},
	)
	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(exec.New(exec.Init{Ino: 2}), goChannelOffsets())
	probes := tracer.GoProbes()
	for _, symbol := range goChannelLinkProbeSymbols() {
		require.Contains(t, probes, symbol)
	}
}

func TestProcessBinarySelectsRecordedChannelOffsetState(t *testing.T) {
	tracer := &Tracer{
		goChannelOffsetsByIno: map[uint64]bool{
			1: true,
			2: false,
		},
	}

	tracer.ProcessBinary(exec.New(exec.Init{Ino: 1}))
	assert.True(t, tracer.goChannelLinkProbesEnabled())

	tracer.ProcessBinary(exec.New(exec.Init{Ino: 2}))
	assert.False(t, tracer.goChannelLinkProbesEnabled())

	tracer.ProcessBinary(nil)
	assert.False(t, tracer.goChannelLinkProbesEnabled())
}

func goChannelOffsets() *goexec.Offsets {
	return &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.HchanDataqsizPos: uint64(8),
		goexec.HchanSendxPos:    uint64(48),
		goexec.HchanRecvxPos:    uint64(56),
	}}
}

func goChannelLinkProbeSymbols() []string {
	return []string{
		"runtime.chansend1",
		"runtime.chanrecv1",
		"runtime.chanrecv2",
	}
}

func assertNoGoChannelLinkProbes(t *testing.T, probes map[string][]*ebpfcommon.ProbeDesc) {
	t.Helper()

	for _, symbol := range goChannelLinkProbeSymbols() {
		assert.NotContains(t, probes, symbol)
	}
}

func disableContextPropagationForTest(t *testing.T) {
	t.Helper()

	previous := ebpfcommon.IntegrityModeOverride
	ebpfcommon.IntegrityModeOverride = true
	t.Cleanup(func() {
		ebpfcommon.IntegrityModeOverride = previous
	})
}
