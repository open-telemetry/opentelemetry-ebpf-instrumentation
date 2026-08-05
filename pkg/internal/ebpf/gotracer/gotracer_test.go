// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"bytes"
	"debug/elf"
	"errors"
	"io"
	"log/slog"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/internal/test/tools"
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfsampling "go.opentelemetry.io/obi/pkg/internal/ebpf/sampling"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

func testGoExecutableKey(ino uint64) goExecutableKey {
	return goExecutableKey{Ino: ino}
}

func testGoExecutableKeyFor(fileInfo *exec.FileInfo) goExecutableKey {
	key, _ := goExecutableKeyFor(fileInfo)
	return key
}

func TestGoChannelLinkProbesRequireChannelOffsets(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		log:                          slog.New(slog.NewTextHandler(io.Discard, nil)),
		goChannelOffsetsByExecutable: map[goExecutableKey]bool{},
	}

	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(
		exec.New(exec.Init{Ino: 1}),
		&goexec.Offsets{Field: goexec.FieldOffsets{
			goexec.HchanQcountPos:   uint64(0),
			goexec.HchanDataqsizPos: uint64(8),
			goexec.HchanSendxPos:    uint64(48),
		}},
	)
	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(exec.New(exec.Init{Ino: 2}), goChannelOffsets())
	probes := tracer.GoProbes()
	for _, symbol := range GoChannelLinkProbeSymbols() {
		require.Contains(t, probes, symbol)
	}
}

func TestGoHTTP2ServerOffsetsGateProbes(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		log:                              slog.New(slog.NewTextHandler(io.Discard, nil)),
		goHTTP2ServerOffsetsByExecutable: map[goExecutableKey]goHTTP2ServerOffsetAvailability{},
	}
	for _, symbol := range goHTTP2ServerProbeSymbols {
		assert.NotContains(t, tracer.GoProbes(), symbol)
	}

	fileInfo := exec.New(exec.Init{Ino: 7})
	tracer.ProcessBinary(fileInfo)
	tracer.recordGoHTTP2ServerOffsetAvailability(fileInfo, goHTTP2ServerOffsetAvailability{xNet: true})
	for _, symbol := range goHTTP2XNetServerProbeSymbols {
		require.Contains(t, tracer.GoProbes(), symbol)
	}
	for _, symbol := range goHTTP2VendoredServerProbeSymbols {
		assert.NotContains(t, tracer.GoProbes(), symbol)
	}

	tracer.recordGoHTTP2ServerOffsetAvailability(fileInfo, goHTTP2ServerOffsetAvailability{vendored: true})
	for _, symbol := range goHTTP2XNetServerProbeSymbols {
		assert.NotContains(t, tracer.GoProbes(), symbol)
	}
	for _, symbol := range goHTTP2VendoredServerProbeSymbols {
		require.Contains(t, tracer.GoProbes(), symbol)
	}

	xNetProcessHeaders := &ebpf.Program{}
	vendoredProcessHeaders := &ebpf.Program{}
	xNetProcessHeadersReturns := &ebpf.Program{}
	vendoredProcessHeadersReturns := &ebpf.Program{}
	tracer.bpfObjects.ObiUprobeHttp2ServerProcessHeaders = xNetProcessHeaders
	tracer.bpfObjects.ObiUprobeHttp2ServerProcessHeadersVendored = vendoredProcessHeaders
	tracer.bpfObjects.ObiUprobeHttp2ServerProcessHeadersReturns = xNetProcessHeadersReturns
	tracer.bpfObjects.ObiUprobeHttp2ServerProcessHeadersReturnsVendored = vendoredProcessHeadersReturns
	tracer.recordGoHTTP2ServerOffsetAvailability(fileInfo, goHTTP2ServerOffsetAvailability{
		xNet: true, vendored: true,
	})
	probes := tracer.GoProbes()
	assert.Same(t, xNetProcessHeaders,
		probes["golang.org/x/net/http2.(*serverConn).processHeaders"][0].Start)
	assert.Same(t, xNetProcessHeadersReturns,
		probes["golang.org/x/net/http2.(*serverConn).processHeaders"][0].End)
	assert.Same(t, vendoredProcessHeaders,
		probes["net/http.(*http2serverConn).processHeaders"][0].Start)
	assert.Same(t, vendoredProcessHeadersReturns,
		probes["net/http.(*http2serverConn).processHeaders"][0].End)
}

func TestRegisterGoHTTP2ServerOffsetsTracksImplementationsIndependently(t *testing.T) {
	offsets := &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.ReqTLSPos:                      uint64(112),
		goexec.ScMaxClientStreamIDPos:         uint64(472),
		goexec.ScMaxClientStreamIDVendoredPos: uint64(480),
	}}
	var offTable BpfOffTableT

	available := registerGoHTTP2ServerOffsets(&offTable, offsets)
	require.True(t, available.xNet)
	require.True(t, available.vendored)
	assert.Equal(t, uint64(112), offTable.Table[goexec.ReqTLSPos])
	assert.Equal(t, uint64(472), offTable.Table[goexec.ScMaxClientStreamIDPos])
	assert.Equal(t, uint64(480), offTable.Table[goexec.ScMaxClientStreamIDVendoredPos])

	delete(offsets.Field, goexec.ScMaxClientStreamIDPos)
	available = registerGoHTTP2ServerOffsets(&offTable, offsets)
	assert.False(t, available.xNet)
	assert.True(t, available.vendored)

	offsets.Field[goexec.ScMaxClientStreamIDPos] = uint64(472)
	delete(offsets.Field, goexec.ScMaxClientStreamIDVendoredPos)
	available = registerGoHTTP2ServerOffsets(&offTable, offsets)
	assert.True(t, available.xNet)
	assert.False(t, available.vendored)

	offsets.Field[goexec.ScMaxClientStreamIDVendoredPos] = uint64(480)
	delete(offsets.Field, goexec.ReqTLSPos)
	available = registerGoHTTP2ServerOffsets(&offTable, offsets)
	assert.False(t, available.xNet)
	assert.False(t, available.vendored)
}

func TestGoHpackTraceparentProbesAreOptional(t *testing.T) {
	program := &ebpf.Program{}
	tracer := &Tracer{}
	tracer.bpfObjects.ObiUprobeHpackEncoderWriteField = program
	probes := map[string][]*ebpfcommon.ProbeDesc{}

	tracer.addGoHpackTraceparentProbes(probes)

	for _, symbol := range goHpackEncoderWriteFieldProbeSymbols {
		descriptors := probes[symbol]
		require.Len(t, descriptors, 1)
		assert.False(t, descriptors[0].Required)
		assert.Same(t, program, descriptors[0].Start)
		assert.Nil(t, descriptors[0].End)
	}
}

func TestMissingGoChannelOffsetsUseSentinel(t *testing.T) {
	var offTable BpfOffTableT

	initMissingGoChannelOffsets(&offTable)

	for _, field := range goChannelOffsetFields {
		assert.Equal(t, missingGoOffset, offTable.Table[field])
	}
	assert.Zero(t, offTable.Table[goexec.ConnFdPos])
}

func TestMissingGRPCWriterOffsetsAllowResolvedZero(t *testing.T) {
	var offTable BpfOffTableT

	initMissingGRPCWriterOffsets(&offTable)

	for _, field := range []goexec.GoOffset{
		goexec.GrpcTransportBufWriterBufPos,
		goexec.GrpcTransportBufWriterOffsetPos,
		goexec.GrpcTransportBufWriterConnPos,
	} {
		assert.Equal(t, missingGoOffset, offTable.Table[field])
	}

	// grpc-go 1.40 through 1.57 places bufWriter.buf at offset zero. A
	// resolved zero must replace the missing sentinel so the retained direct
	// TLS publication path remains enabled for those versions.
	offTable.Table[goexec.GrpcTransportBufWriterBufPos] = 0
	assert.Zero(t, offTable.Table[goexec.GrpcTransportBufWriterBufPos])
	assert.NotEqual(
		t,
		missingGoOffset,
		offTable.Table[goexec.GrpcTransportBufWriterBufPos],
	)
}

func TestOutgoingHandoffMetadataUsesBoundedExactHints(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	lruMaps := map[string]uint32{
		"go_outgoing_trace_handoffs":         24,
		"grpc_client_request_states":         40,
		"grpc_client_request_handoff_states": 40,
		"grpc_client_request_handoffs":       48,
		"grpc_client_stream_requests":        16,
		"grpc_client_recv_streams":           24,
		"cached_grpc_client_connections":     24,
		"ongoing_streams":                    24,
		"transport_new_client_invocations":   24,
		"grpc_framer_invocation_map":         24,
		"grpc_conn_ptr_to_conn":              24,
		"pending_h2_invocations":             24,
		"header_req_map":                     32,
		"http2_req_map":                      24,
	}
	for name, keySize := range lruMaps {
		m := spec.Maps[name]
		require.NotNil(t, m, "missing map %s", name)
		assert.Equal(t, ebpf.LRUHash, m.Type, name)
		assert.Equal(t, keySize, m.KeySize, name)
		assert.NotZero(t, m.MaxEntries, name)
	}

	for _, name := range []string{
		"go_outgoing_trace_handoff_owner_claims",
		"grpc_client_request_handoff_claims",
		"grpc_client_stream_request_claims",
	} {
		m := spec.Maps[name]
		require.NotNil(t, m, "missing map %s", name)
		assert.Equal(t, ebpf.Hash, m.Type, name)
		assert.NotZero(t, m.MaxEntries, name)
	}
}

func TestRegisterBufReaderOffsetsIncludesReadPosition(t *testing.T) {
	offsets := &goexec.Offsets{
		Field: goexec.FieldOffsets{
			goexec.BufReaderBufPos: uint64(24),
			goexec.BufReaderRPos:   uint64(40),
			goexec.BufReaderWPos:   uint64(48),
		},
	}
	var offTable BpfOffTableT

	registerBufReaderOffsets(&offTable, offsets)

	assert.Equal(t, uint64(24), offTable.Table[goexec.BufReaderBufPos])
	assert.Equal(t, uint64(40), offTable.Table[goexec.BufReaderRPos])
	assert.Equal(t, uint64(48), offTable.Table[goexec.BufReaderWPos])
}

func TestGoAutoSDKFunctionsAvailable(t *testing.T) {
	offsets := &goexec.Offsets{
		Funcs: map[string]goexec.FuncOffsets{},
		Field: goexec.FieldOffsets{
			goexec.SpanContextTraceIDPos:      uint64(0),
			goexec.SpanContextSpanIDPos:       uint64(16),
			goexec.SpanContextTraceFlagsPos:   uint64(24),
			goexec.AutoSDKSpanContextPos:      uint64(80),
			goexec.AutoSDKActivationSupported: uint64(1),
		},
		AutoSDKTypes: validGoAutoSDKTypeInfo(),
	}
	for _, symbol := range goAutoSDKSharedProbeSymbols {
		offsets.Funcs[symbol] = goexec.FuncOffsets{}
	}
	for _, symbol := range goAutoSDKGlobalProbeSymbols {
		offsets.Funcs[symbol] = goexec.FuncOffsets{}
	}
	offsets.Funcs[goAutoSDKGlobalEntryProbeSymbol] = goexec.FuncOffsets{Admission: 0x1234}
	offsets.Funcs[goAutoSDKStartProbeSymbols[0]] = goexec.FuncOffsets{}
	assert.True(t, goAutoSDKFunctionsAvailable(offsets))
	directRequired, available := goAutoSDKAttachmentSymbols(offsets)
	require.True(t, available)
	assert.Contains(t, directRequired, goAutoSDKStartProbeSymbols[0])
	assert.NotContains(t, directRequired, goAutoSDKStartProbeSymbols[1])
	globalRequired, globalAvailable := goAutoSDKGlobalAttachmentSymbols(offsets)
	require.True(t, globalAvailable)
	assert.ElementsMatch(
		t,
		append(
			append([]string{}, goAutoSDKSharedProbeSymbols...),
			goAutoSDKGlobalProbeSymbols...,
		),
		globalRequired,
	)

	offsets.Funcs[goAutoSDKStartProbeSymbols[1]] = goexec.FuncOffsets{}
	directRequired, available = goAutoSDKAttachmentSymbols(offsets)
	require.True(t, available)
	assert.Contains(t, directRequired, goAutoSDKStartProbeSymbols[0])
	assert.NotContains(t, directRequired, goAutoSDKStartProbeSymbols[1])

	const optionalProbe = "go.opentelemetry.io/auto/sdk.(*span).SetName"
	offsets.Funcs[optionalProbe] = goexec.FuncOffsets{}
	directRequired, available = goAutoSDKAttachmentSymbols(offsets)
	require.True(t, available)
	assert.NotContains(t, directRequired, optionalProbe)
	globalRequired, globalAvailable = goAutoSDKGlobalAttachmentSymbols(offsets)
	require.True(t, globalAvailable)
	assert.NotContains(t, globalRequired, optionalProbe)
	delete(offsets.Funcs, optionalProbe)

	for _, missing := range goAutoSDKSharedProbeSymbols {
		delete(offsets.Funcs, missing)
		assert.False(t, goAutoSDKFunctionsAvailable(offsets), missing)
		_, globalAvailable = goAutoSDKGlobalAttachmentSymbols(offsets)
		assert.False(t, globalAvailable, missing)
		offsets.Funcs[missing] = goexec.FuncOffsets{}
	}

	offsets.Funcs[goAutoSDKGlobalEntryProbeSymbol] = goexec.FuncOffsets{}
	assert.True(t, goAutoSDKFunctionsAvailable(offsets),
		"global admission must not gate direct activation")
	_, globalAvailable = goAutoSDKGlobalAttachmentSymbols(offsets)
	assert.False(t, globalAvailable,
		"function-entry attachment cannot guard the interior flag load")
	offsets.Funcs[goAutoSDKGlobalEntryProbeSymbol] = goexec.FuncOffsets{Admission: 0x1234}

	for _, symbol := range goAutoSDKGlobalProbeSymbols {
		function := offsets.Funcs[symbol]
		delete(offsets.Funcs, symbol)
		assert.True(t, goAutoSDKFunctionsAvailable(offsets), symbol)
		_, globalAvailable = goAutoSDKGlobalAttachmentSymbols(offsets)
		assert.False(t, globalAvailable, symbol)
		offsets.Funcs[symbol] = function
	}

	delete(offsets.Funcs, goAutoSDKStartProbeSymbols[0])
	assert.True(t, goAutoSDKFunctionsAvailable(offsets))
	delete(offsets.Funcs, goAutoSDKStartProbeSymbols[1])
	assert.False(t, goAutoSDKFunctionsAvailable(offsets))
	_, globalAvailable = goAutoSDKGlobalAttachmentSymbols(offsets)
	assert.True(t, globalAvailable,
		"global activation must not require a direct public Start wrapper")
	offsets.Funcs[goAutoSDKStartProbeSymbols[1]] = goexec.FuncOffsets{}

	delete(offsets.Field, goexec.SpanContextTraceFlagsPos)
	assert.False(t, goAutoSDKFunctionsAvailable(offsets))
	_, globalAvailable = goAutoSDKGlobalAttachmentSymbols(offsets)
	assert.False(t, globalAvailable)
	offsets.Field[goexec.SpanContextTraceFlagsPos] = uint64(24)

	offsets.AutoSDKTypes = goexec.GoAutoSDKTypeInfo{}
	assert.False(t, goAutoSDKFunctionsAvailable(offsets))
	_, globalAvailable = goAutoSDKGlobalAttachmentSymbols(offsets)
	assert.False(t, globalAvailable)
}

func TestGoAutoSDKDirectOnlyExecutableEligibility(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux ELF inspection only")
	}

	binaryPath := filepath.Join(t.TempDir(), "auto-sdk-direct")
	sourcePath := filepath.Join(
		tools.ProjectDir(),
		"pkg/internal/goexec/testdata/auto_sdk_direct/main.go",
	)
	cmd := osexec.Command(
		"go",
		"build",
		"-ldflags",
		"-s -w",
		"-o",
		binaryPath,
		sourcePath,
	)
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "building direct Auto SDK fixture:\n%s", output)

	elfFile, err := elf.Open(binaryPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, elfFile.Close())
	})
	fileInfo := exec.New(exec.Init{
		CmdExePath: binaryPath,
		ELF:        elfFile,
	})
	symbols := append(
		append(
			append([]string{}, goAutoSDKSharedProbeSymbols...),
			goAutoSDKStartProbeSymbols...,
		),
		goAutoSDKGlobalProbeSymbols...,
	)
	offsets, err := goexec.InspectOffsets(fileInfo, symbols)
	require.NoError(t, err)

	directRequired, directAvailable := goAutoSDKAttachmentSymbols(offsets)
	require.True(t, directAvailable)
	assert.NotEmpty(t, directRequired)
	globalRequired, globalAvailable := goAutoSDKGlobalAttachmentSymbols(offsets)
	assert.False(t, globalAvailable)
	assert.Empty(t, globalRequired)
	for _, symbol := range goAutoSDKGlobalProbeSymbols {
		assert.NotContains(t, offsets.Funcs, symbol)
	}
}

func TestGoAutoSDKRequiredTailCallsFailClosed(t *testing.T) {
	programs := make([]*ebpf.Program, goAutoSDKLastRequiredTailCall+1)
	for i := range programs {
		programs[i] = &ebpf.Program{}
	}

	tests := []struct {
		name      string
		programs  []*ebpf.Program
		failIndex int
		wantReady bool
	}{
		{
			name:      "all required programs installed",
			programs:  programs,
			failIndex: -1,
			wantReady: true,
		},
		{
			name:      "unrelated tail call fails",
			programs:  programs,
			failIndex: goAutoSDKFirstRequiredTailCall - 1,
			wantReady: true,
		},
		{
			name:      "first required tail call fails",
			programs:  programs,
			failIndex: goAutoSDKFirstRequiredTailCall,
			wantReady: false,
		},
		{
			name:      "second required tail call fails",
			programs:  programs,
			failIndex: goAutoSDKFirstRequiredTailCall + 1,
			wantReady: false,
		},
		{
			name:      "third required tail call fails",
			programs:  programs,
			failIndex: goAutoSDKFirstRequiredTailCall + 2,
			wantReady: false,
		},
		{
			name:      "last required tail call fails",
			programs:  programs,
			failIndex: goAutoSDKLastRequiredTailCall,
			wantReady: false,
		},
		{
			name:      "required tail call is missing",
			programs:  programs[:goAutoSDKLastRequiredTailCall],
			failIndex: -1,
			wantReady: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ready := installGoTailCalls(
				tc.programs,
				func(index uint32, _ *ebpf.Program) error {
					if int(index) == tc.failIndex {
						return errors.New("test update failure")
					}
					return nil
				},
			)
			assert.Equal(t, tc.wantReady, ready)

			tracer := &Tracer{
				goAutoSDKPreAdmissionReady: ready,
				goAutoSDKTailCallsReady:    ready,
				goAutoSDKReadyByExecutable: map[goExecutableKey]bool{testGoExecutableKey(1): true},
				goAutoSDKDiscoveryReady:    true,
			}
			assert.Equal(
				t,
				tc.wantReady,
				tracer.goAutoSDKActivationReady(testGoExecutableKey(1), true, true, true, true, false),
			)
		})
	}
}

func TestGoTailCallTableMatchesSharedSlots(t *testing.T) {
	programs := make([]*ebpf.Program, goTailCallCount)
	for i := range programs {
		programs[i] = &ebpf.Program{}
	}
	programs[12] = nil // reserved shared slot; the server-finalize trampoline was removed
	tracer := &Tracer{
		bpfObjects: BpfObjects{
			BpfPrograms: BpfPrograms{
				ObiProtocolHttp:                                  programs[0],
				ObiContinueProtocolHttp:                          programs[1],
				ObiContinue2ProtocolHttp:                         programs[2],
				ObiContinueProtocolHttpTp:                        programs[3],
				ObiProtocolTcp:                                   programs[4],
				ObiHandleBufWithArgs:                             programs[5],
				ObiContinueNetfdRead:                             programs[6],
				ObiProtocolHttp2:                                 programs[7],
				ObiProtocolHttp2GrpcFrames:                       programs[8],
				ObiProtocolHttp2GrpcHandleStartFrame:             programs[9],
				ObiProtocolHttp2GrpcHandleEndFrame:               programs[10],
				ObiProtocolHttp2GrpcHandleStartFrameServer:       programs[11],
				ObiLargeBufEmitContinue:                          programs[13],
				ObiProtocolHttp2GrpcHandleStartFrameServerCommit: programs[14],
				ObiUprobeGoSpanStartAttributes:                   programs[15],
				ObiUprobeGoSpanStartApplyAttributes:              programs[16],
				ObiUprobeGoSpanStartRoute:                        programs[17],
				ObiUprobeGoSpanSetAttributes:                     programs[18],
				ObiProtocolHttp2GrpcValidateServerTraceparent:    programs[19],
				ObiHandleHttpContinuation:                        programs[20],
				ObiProtocolHttp2GrpcFinishClient:                 programs[21],
				ObiProtocolHttp2GrpcParseServerHeaders:           programs[22],
			},
		},
	}

	actual := tracer.tailCallPrograms()
	require.Len(t, actual, goTailCallCount)
	for i := range programs {
		assert.Same(t, programs[i], actual[i], "tail call slot %d", i)
	}
}

func TestRecordGoProbeAttachmentsTracksAutoSDKGroupsIndependently(t *testing.T) {
	const ino = uint64(42)
	fileInfo := exec.New(exec.Init{Ino: ino, Pid: 123, CmdExePath: "/test/server"})
	directRequired := append(
		append([]string{}, goAutoSDKSharedProbeSymbols...),
		goAutoSDKStartProbeSymbols[0],
	)
	globalRequired := append(
		append([]string{}, goAutoSDKSharedProbeSymbols...),
		goAutoSDKGlobalProbeSymbols...,
	)
	tracer := &Tracer{
		log:                                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		goAutoSDKEligibleByExecutable:       map[goExecutableKey]bool{testGoExecutableKey(ino): true},
		goAutoSDKReadyByExecutable:          map[goExecutableKey]bool{},
		goAutoSDKGlobalEligibleByExecutable: map[goExecutableKey]bool{testGoExecutableKey(ino): true},
		goAutoSDKGlobalReadyByExecutable:    map[goExecutableKey]bool{},
		goAutoSDKProbesByExecutable:         map[goExecutableKey][]string{testGoExecutableKey(ino): directRequired},
		goAutoSDKGlobalProbesByExecutable:   map[goExecutableKey][]string{testGoExecutableKey(ino): globalRequired},
	}
	attached := map[string]bool{"unrelated.optional": false}
	for _, symbol := range append(directRequired, globalRequired...) {
		attached[symbol] = true
	}

	tracer.RecordGoProbeAttachments(fileInfo, attached)
	assert.True(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)])
	assert.True(t, tracer.goAutoSDKGlobalReadyByExecutable[testGoExecutableKey(ino)])

	for _, missing := range goAutoSDKSharedProbeSymbols {
		attached[missing] = false
		tracer.RecordGoProbeAttachments(fileInfo, attached)
		assert.False(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)], missing)
		assert.False(t, tracer.goAutoSDKGlobalReadyByExecutable[testGoExecutableKey(ino)], missing)
		attached[missing] = true
	}

	attached[goAutoSDKStartProbeSymbols[0]] = false
	tracer.RecordGoProbeAttachments(fileInfo, attached)
	assert.False(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)])
	assert.True(t, tracer.goAutoSDKGlobalReadyByExecutable[testGoExecutableKey(ino)])
	attached[goAutoSDKStartProbeSymbols[0]] = true

	attached[goAutoSDKGlobalProbeSymbols[0]] = false
	tracer.RecordGoProbeAttachments(fileInfo, attached)
	assert.True(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)])
	assert.False(t, tracer.goAutoSDKGlobalReadyByExecutable[testGoExecutableKey(ino)])
	attached[goAutoSDKGlobalProbeSymbols[0]] = true

	tracer.goAutoSDKEligibleByExecutable[testGoExecutableKey(ino)] = false
	tracer.RecordGoProbeAttachments(fileInfo, attached)
	assert.False(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)])
	assert.True(t, tracer.goAutoSDKGlobalReadyByExecutable[testGoExecutableKey(ino)])

	tracer.goAutoSDKEligibleByExecutable[testGoExecutableKey(ino)] = true
	tracer.goAutoSDKGlobalEntryBarrierClosed = true
	tracer.RecordGoProbeAttachments(fileInfo, attached)
	assert.True(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)])
	assert.False(t, tracer.goAutoSDKGlobalReadyByExecutable[testGoExecutableKey(ino)])

	tracer.goAutoSDKDirectEntryBarrierClosed = true
	tracer.RecordGoProbeAttachments(fileInfo, attached)
	assert.False(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)])
	assert.False(t, tracer.goAutoSDKGlobalReadyByExecutable[testGoExecutableKey(ino)])
}

func TestGoExecutableMetadataSeparatesDevicesWithSameInode(t *testing.T) {
	const ino = uint64(42)
	first := exec.New(exec.Init{Dev: 7, Ino: ino})
	second := exec.New(exec.Init{Dev: 9, Ino: ino})
	firstKey := testGoExecutableKeyFor(first)
	secondKey := testGoExecutableKeyFor(second)
	require.NotEqual(t, firstKey, secondKey)
	assert.Equal(t, uintptr(16), unsafe.Sizeof(firstKey))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(firstKey.Ino))

	firstType := validGoAutoSDKTypeInfo()
	secondType := firstType
	secondType.TraceContextKeyType++
	tracer := &Tracer{
		goChannelOffsetsByExecutable: map[goExecutableKey]bool{
			firstKey:  false,
			secondKey: true,
		},
		goRuntimeMetricMaskByExecutable: map[goExecutableKey]uint64{
			firstKey:  goRuntimeMetricBaseMask,
			secondKey: goRuntimeMetricBaseMask | goRuntimeMetricHeapSnapshotMask,
		},
		goAutoSDKEligibleByExecutable: map[goExecutableKey]bool{
			firstKey:  true,
			secondKey: true,
		},
		goAutoSDKProbesByExecutable: map[goExecutableKey][]string{
			firstKey:  {"first.required"},
			secondKey: {"second.required"},
		},
		goAutoSDKTypesByExecutable: map[goExecutableKey]goexec.GoAutoSDKTypeInfo{
			firstKey:  firstType,
			secondKey: secondType,
		},
	}

	tracer.RecordGoProbeAttachments(first, map[string]bool{"first.required": true})
	tracer.RecordGoProbeAttachments(second, map[string]bool{"second.required": false})
	assert.True(t, tracer.goAutoSDKReadyByExecutable[firstKey])
	assert.False(t, tracer.goAutoSDKReadyByExecutable[secondKey])
	assert.Equal(t, firstType, tracer.goAutoSDKTypesByExecutable[firstKey])
	assert.Equal(t, secondType, tracer.goAutoSDKTypesByExecutable[secondKey])

	tracer.ProcessBinary(first)
	assert.False(t, tracer.goProbeState().channelLinks)
	assert.False(t, tracer.goProbeState().runtimeHeapSnapshot)
	tracer.ProcessBinary(second)
	assert.True(t, tracer.goProbeState().channelLinks)
	assert.True(t, tracer.goProbeState().runtimeHeapSnapshot)
}

func TestGoExecutableKeyUsesCanonicalDeviceComponents(t *testing.T) {
	fileInfo := exec.New(exec.Init{Dev: unix.Mkdev(8, 1), Ino: 123})
	key := testGoExecutableKeyFor(fileInfo)

	assert.Equal(t, uint32(8), key.DevMajor)
	assert.Equal(t, uint32(1), key.DevMinor)
	assert.Equal(t, uint64(123), key.Ino)
	assert.Equal(t, uintptr(16), unsafe.Sizeof(key))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(key.Ino))
}

type fakeGoSpanOptionMap struct {
	values      map[goSpanOptionFunctionKey]uint8
	putCalls    int
	deleteCalls int
}

type fakeGoProcessGenerationMap struct {
	values    map[uint32]goProcessGenerationValue
	putErr    error
	deleteErr error
}

type recordingServiceFilter struct {
	allowed int
	blocked int
}

type fakeSamplerLifecycleManager struct {
	blockCleanupSafe    bool
	blockClearsFallback bool
	blockCalls          int
	blockStartTimes     []uint64
	fallbackUnsafe      bool
}

func (*fakeSamplerLifecycleManager) InstallGlobal() bool {
	return true
}

func (*fakeSamplerLifecycleManager) AllowPIDForProcess(
	app.PID,
	uint32,
	uint64,
	*services.CanonicalSampler,
	bool,
) bool {
	return false
}

func (m *fakeSamplerLifecycleManager) FallbackSafeForProcessIncarnation(
	app.PID,
	uint32,
	uint64,
) bool {
	return !m.fallbackUnsafe
}

func (*fakeSamplerLifecycleManager) EnableAutoSDK(app.PID, uint32) bool {
	return false
}

func (*fakeSamplerLifecycleManager) EnableAutoSDKWithSetup(
	app.PID,
	uint32,
	func(uint32, uint64, uint32) bool,
) bool {
	return false
}

func (*fakeSamplerLifecycleManager) EnableAutoSDKWithSetupMode(
	app.PID,
	uint32,
	bool,
	func(uint32, uint64, uint32) bool,
) bool {
	return false
}

func (*fakeSamplerLifecycleManager) QuiesceAutoSDKForProcess(app.PID, uint32, uint64) bool {
	return true
}

func (m *fakeSamplerLifecycleManager) BlockPIDForProcess(
	_ app.PID,
	_ uint32,
	startTime uint64,
) bool {
	m.blockCalls++
	m.blockStartTimes = append(m.blockStartTimes, startTime)
	if m.blockCleanupSafe && m.blockClearsFallback {
		m.fallbackUnsafe = false
	}
	return m.blockCleanupSafe
}

func (f *recordingServiceFilter) AllowPID(
	app.PID,
	uint32,
	*exec.FileInfo,
	ebpfcommon.PIDType,
) {
	f.allowed++
}

func (f *recordingServiceFilter) BlockPID(app.PID, uint32) {
	f.blocked++
}

func (*recordingServiceFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool {
	return false
}

func (*recordingServiceFilter) Filter(spans []request.Span) []request.Span {
	return spans
}

func (*recordingServiceFilter) CurrentPIDs(
	ebpfcommon.PIDType,
) map[uint32]map[app.PID]svc.Attrs {
	return nil
}

func (m *fakeGoSpanOptionMap) Put(key, value any) error {
	m.putCalls++
	m.values[key.(goSpanOptionFunctionKey)] = value.(uint8)
	return nil
}

func (m *fakeGoSpanOptionMap) Delete(key any) error {
	m.deleteCalls++
	delete(m.values, key.(goSpanOptionFunctionKey))
	return nil
}

func (m *fakeGoProcessGenerationMap) Put(key, value any) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.values[key.(uint32)] = value.(goProcessGenerationValue)
	return nil
}

func (m *fakeGoProcessGenerationMap) Delete(key any) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	hostPID := key.(uint32)
	if _, ok := m.values[hostPID]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.values, hostPID)
	return nil
}

func TestGoProcessGenerationFollowsProcessIncarnation(t *testing.T) {
	generations := []uint64{11, 22, 33, 44}
	next := 0
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{},
	}
	tracer := &Tracer{
		goProcessGenerations:     generationMap,
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{},
		newGoProcessGeneration: func() (uint64, error) {
			generation := generations[next]
			next++
			return generation, nil
		},
	}
	process := runtimeMetricTargetKey{pid: 123, ns: 7}
	firstIncarnation := exec.New(exec.Init{Pid: 123, Ns: 7, StartTime: 10000000})

	require.True(t, tracer.registerGoProcessGenerationForHostPID(
		process, 1001, firstIncarnation,
	))
	assert.Equal(t, uint64(11), generationMap.values[1001].Generation)
	assert.Equal(t, uint64(10000000), generationMap.values[1001].StartTime)

	require.True(t, tracer.registerGoProcessGenerationForHostPID(
		process, 1001, firstIncarnation,
	))
	assert.Equal(t, uint64(11), generationMap.values[1001].Generation)
	assert.Equal(t, 1, next, "repeated admission of one process must reuse its generation")

	secondIncarnation := exec.New(exec.Init{Pid: 123, Ns: 7, StartTime: 20000000})
	require.True(t, tracer.registerGoProcessGenerationForHostPID(
		process, 1001, secondIncarnation,
	))
	assert.Equal(t, uint64(22), generationMap.values[1001].Generation)
	assert.Equal(t, uint64(20000000), generationMap.values[1001].StartTime)

	require.True(t, tracer.registerGoProcessGenerationForHostPID(
		process, 2002, secondIncarnation,
	))
	assert.NotContains(t, generationMap.values, uint32(1001))
	assert.Equal(t, uint64(33), generationMap.values[2002].Generation)

	tracer.retireGoProcessGeneration(process.pid, process.ns)
	assert.NotContains(t, generationMap.values, uint32(2002))
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)

	require.True(t, tracer.registerGoProcessGenerationForHostPID(
		process, 2002, secondIncarnation,
	))
	assert.Equal(t, uint64(44), generationMap.values[2002].Generation)
}

func TestGoProcessGenerationDeleteFailureWritesDisabledValue(t *testing.T) {
	deleteErr := errors.New("delete failed")
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			1001: {Generation: 11, StartTime: 10000000},
		},
		deleteErr: deleteErr,
	}
	process := runtimeMetricTargetKey{pid: 123, ns: 7}
	tracer := &Tracer{
		goProcessGenerations: generationMap,
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{
			process: {
				hostPID:    1001,
				generation: 11,
				fileInfo: exec.New(exec.Init{
					Pid: 123, Ns: 7, StartTime: 10000000,
				}),
			},
		},
	}

	tracer.retireGoProcessGeneration(process.pid, process.ns)

	assert.Equal(t, uint64(0), generationMap.values[1001].Generation)
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
}

func TestGoProcessGenerationCleanupDebtBlocksReuse(t *testing.T) {
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			1001: {Generation: 11, StartTime: 10000000},
		},
		deleteErr: errors.New("delete failed"),
		putErr:    errors.New("put failed"),
	}
	process := runtimeMetricTargetKey{pid: 123, ns: 7}
	fileInfo := exec.New(exec.Init{Pid: 123, Ns: 7, StartTime: 10000000})
	tracer := &Tracer{
		goProcessGenerations: generationMap,
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{
			process: {
				hostPID:    1001,
				generation: 11,
				fileInfo:   fileInfo,
			},
		},
		newGoProcessGeneration: func() (uint64, error) {
			return 22, nil
		},
	}

	tracer.retireGoProcessGeneration(process.pid, process.ns)
	assert.True(t, tracer.goProcessGenerationByPID[process].retired)
	assert.Equal(t, uint64(11), generationMap.values[1001].Generation)
	assert.False(t, tracer.registerGoProcessGenerationForHostPID(process, 1001, fileInfo))

	generationMap.deleteErr = nil
	generationMap.putErr = nil
	require.True(t, tracer.registerGoProcessGenerationForHostPID(process, 1001, fileInfo))
	assert.Equal(t, uint64(22), generationMap.values[1001].Generation)
	assert.False(t, tracer.goProcessGenerationByPID[process].retired)
}

func TestGoProcessGenerationResolverFailureRetiresCachedState(t *testing.T) {
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			1001: {Generation: 11, StartTime: 10000000},
		},
	}
	process := runtimeMetricTargetKey{pid: 123, ns: 7}
	fileInfo := exec.New(exec.Init{Pid: 123, Ns: 7, StartTime: 10000000})
	tracer := &Tracer{
		goProcessGenerations: generationMap,
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{
			process: {
				hostPID:    1001,
				generation: 11,
				fileInfo:   fileInfo,
			},
		},
		resolveGoProcessHostPID: func(app.PID, uint32) (uint32, error) {
			return 0, errors.New("resolve failed")
		},
	}

	assert.False(t, tracer.registerGoProcessGeneration(process.pid, process.ns, fileInfo))
	assert.NotContains(t, generationMap.values, uint32(1001))
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
}

func TestGoProcessGenerationPutFailureClearsUntrackedState(t *testing.T) {
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			1001: {Generation: 99, StartTime: 10000000},
		},
		putErr: errors.New("put failed"),
	}
	process := runtimeMetricTargetKey{pid: 123, ns: 7}
	tracer := &Tracer{
		goProcessGenerations:     generationMap,
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{},
		newGoProcessGeneration: func() (uint64, error) {
			return 22, nil
		},
	}

	assert.False(t, tracer.registerGoProcessGenerationForHostPID(
		process, 1001, exec.New(exec.Init{Pid: 123, Ns: 7, StartTime: 10000000}),
	))
	assert.NotContains(t, generationMap.values, uint32(1001))
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
}

func TestGoProcessGenerationSourceFailureClearsUntrackedState(t *testing.T) {
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			1001: {Generation: 99, StartTime: 10000000},
		},
	}
	process := runtimeMetricTargetKey{pid: 123, ns: 7}
	tracer := &Tracer{
		goProcessGenerations:     generationMap,
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{},
		newGoProcessGeneration: func() (uint64, error) {
			return 0, errors.New("source failed")
		},
	}

	assert.False(t, tracer.registerGoProcessGenerationForHostPID(
		process, 1001, exec.New(exec.Init{Pid: 123, Ns: 7, StartTime: 10000000}),
	))
	assert.NotContains(t, generationMap.values, uint32(1001))
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
}

func TestGoProcessGenerationHostPIDTakeoverIgnoresDelayedBlock(t *testing.T) {
	generations := []uint64{11, 22}
	next := 0
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{},
	}
	optionMap := &fakeGoSpanOptionMap{
		values: map[goSpanOptionFunctionKey]uint8{},
	}
	typeInfoMap := &fakeGoAutoSDKTypeInfoMap{
		values: map[goProcessKey]BpfGoAutoSdkTypeInfoT{},
	}
	samplerManager := &fakeSamplerLifecycleManager{}
	tracer := &Tracer{
		log:                       slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:                &recordingServiceFilter{},
		samplerManager:            samplerManager,
		goSpanOptionFunctions:     optionMap,
		goAutoSDKTypeInfos:        typeInfoMap,
		goProcessGenerations:      generationMap,
		goProcessGenerationByPID:  map[runtimeMetricTargetKey]goProcessGenerationState{},
		goProcessOwnerByHostPID:   map[uint32]runtimeMetricTargetKey{},
		goSpanOptionKeysByProcess: map[runtimeMetricTargetKey][]goSpanOptionFunctionKey{},
		goAutoSDKTypeInfoKeys:     map[runtimeMetricTargetKey]goProcessKey{},
		newGoProcessGeneration: func() (uint64, error) {
			generation := generations[next]
			next++
			return generation, nil
		},
	}
	retryPaused := make(chan struct{}, 1)
	resumeRetry := make(chan struct{})
	retryResumed := false
	resumeRetryLoop := func() {
		if !retryResumed {
			close(resumeRetry)
			retryResumed = true
		}
	}
	defer func() {
		resumeRetryLoop()
		tracer.goAutoSDKRestoreRetryWG.Wait()
	}()
	tracer.goAutoSDKRestoreRetryPause = func() {
		retryPaused <- struct{}{}
		<-resumeRetry
	}
	first := runtimeMetricTargetKey{pid: 123, ns: 7}
	second := runtimeMetricTargetKey{pid: 123, ns: 8}
	firstOptionKey := goSpanOptionFunctionKey{HostPID: 1001, Generation: 11, Function: 99}
	firstTypeInfoKey := goProcessKey{PID: 1001, Generation: 11}

	require.True(t, tracer.registerGoProcessGenerationForHostPID(
		first, 1001, exec.New(exec.Init{Pid: 123, Ns: 7, StartTime: 10000000}),
	))
	optionMap.values[firstOptionKey] = goSpanOptionKind
	typeInfoMap.values[firstTypeInfoKey] = BpfGoAutoSdkTypeInfoT{}
	tracer.goSpanOptionKeysByProcess[first] = []goSpanOptionFunctionKey{firstOptionKey}
	tracer.goAutoSDKTypeInfoKeys[first] = firstTypeInfoKey

	tracer.BlockPID(first.pid, first.ns)
	select {
	case <-retryPaused:
	case <-time.After(time.Second):
		t.Fatal("restore retry did not pause after the unsafe cleanup")
	}
	assert.Contains(t, optionMap.values, firstOptionKey)
	assert.Contains(t, typeInfoMap.values, firstTypeInfoKey)
	assert.Equal(t, uint64(11), generationMap.values[1001].Generation)
	assert.Equal(t, first, tracer.goProcessOwnerByHostPID[1001])

	require.True(t, tracer.registerGoProcessGenerationForHostPID(
		second, 1001, exec.New(exec.Init{Pid: 123, Ns: 8, StartTime: 20000000}),
	))

	assert.Equal(t, uint64(22), generationMap.values[1001].Generation)
	assert.NotContains(t, tracer.goProcessGenerationByPID, first)
	assert.Equal(t, second, tracer.goProcessOwnerByHostPID[1001])

	samplerManager.blockCleanupSafe = true
	tracer.BlockPID(first.pid, first.ns)
	assert.Empty(t, optionMap.values)
	assert.Empty(t, typeInfoMap.values)
	assert.NotContains(t, tracer.goSpanOptionKeysByProcess, first)
	assert.NotContains(t, tracer.goAutoSDKTypeInfoKeys, first)
	assert.Equal(t, uint64(22), generationMap.values[1001].Generation)
	assert.Equal(t, second, tracer.goProcessOwnerByHostPID[1001])

	resumeRetryLoop()
	tracer.goAutoSDKRestoreRetryWG.Wait()
}

func TestAllowPIDKeepsFallbackWhenSamplerSetupFails(t *testing.T) {
	filter := &recordingServiceFilter{}
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{},
	}
	tracer := &Tracer{
		log:                             slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:                      filter,
		goAutoSDKReadyByExecutable:      map[goExecutableKey]bool{},
		goAutoSDKEligibleByExecutable:   map[goExecutableKey]bool{},
		goSpanOptionFuncsByExecutable:   map[goExecutableKey][]goSpanOptionFunction{},
		goAutoSDKTypesByExecutable:      map[goExecutableKey]goexec.GoAutoSDKTypeInfo{},
		goRuntimeMetricMaskByExecutable: map[goExecutableKey]uint64{},
		goProcessGenerations:            generationMap,
		goProcessGenerationByPID:        map[runtimeMetricTargetKey]goProcessGenerationState{},
		newGoProcessGeneration: func() (uint64, error) {
			return 17, nil
		},
		resolveGoProcessHostPID: func(app.PID, uint32) (uint32, error) {
			return 456, nil
		},
		samplerManager: ebpfsampling.NewManager(
			nil,
			nil,
			nil,
			nil,
			nil,
			services.CanonicalSampler{},
		),
	}
	tracer.SetEventContext(ebpfcommon.NewEBPFEventContext())
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	fileInfo := exec.New(exec.Init{
		Pid:         123,
		StartTime:   10000000,
		ProcessRoot: processRoot,
	})

	admitted := tracer.AllowPIDForProcess(123, 0, fileInfo)

	assert.True(t, admitted)
	assert.Equal(t, 1, filter.allowed)
	assert.Equal(t, uint64(17), generationMap.values[456].Generation)
	assert.Equal(t, uint64(10000000), generationMap.values[456].StartTime)
	assert.Nil(t, tracer.goProcessAdmissions[runtimeMetricTargetKey{pid: fileInfo.Pid(), ns: fileInfo.Ns()}].processRoot)
	unclaimedRoot := fileInfo.TakeProcessRoot()
	require.Same(t, processRoot, unclaimedRoot)
	require.NoError(t, unclaimedRoot.Close())
}

func TestBlockPIDCleansAdmissionAfterGenerationRegistrationFails(t *testing.T) {
	filter := &recordingServiceFilter{}
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{},
		putErr: errors.New("put failed"),
	}
	samplerManager := &fakeSamplerLifecycleManager{blockCleanupSafe: true}
	tracer := &Tracer{
		log:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:               filter,
		samplerManager:           samplerManager,
		goProcessGenerations:     generationMap,
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{},
		goProcessOwnerByHostPID:  map[uint32]runtimeMetricTargetKey{},
		goAutoSDKAdmissions:      map[runtimeMetricTargetKey]goAutoSDKAdmissionState{},
		goAutoSDKQuiescing:       map[runtimeMetricTargetKey]bool{},
		newGoProcessGeneration: func() (uint64, error) {
			return 17, nil
		},
		resolveGoProcessHostPID: func(app.PID, uint32) (uint32, error) {
			return 456, nil
		},
	}
	tracer.SetEventContext(ebpfcommon.NewEBPFEventContext())
	fileInfo := exec.New(exec.Init{
		Pid:       123,
		StartTime: 10000000,
	})
	process := runtimeMetricTargetKey{pid: fileInfo.Pid(), ns: fileInfo.Ns()}

	assert.True(t, tracer.AllowPIDForProcess(process.pid, process.ns, fileInfo))
	assert.Equal(t, 1, filter.allowed)
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
	assert.Equal(
		t,
		goProcessAdmissionState{
			startTime:       fileInfo.StartTime(),
			generationReady: false,
			fileInfo:        fileInfo,
		},
		tracer.goProcessAdmissions[process],
	)
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	tracer.runtimeMetricTargetKeys = map[runtimeMetricTargetKey]BpfPidInfo{
		process: {HostPid: 456, UserPid: uint32(process.pid), Ns: process.ns},
	}
	tracer.BlockPIDForProcess(process.pid, process.ns, fileInfo)

	assert.Equal(t, 1, filter.blocked)
	assert.Equal(t, 1, samplerManager.blockCalls)
	assert.NotContains(t, tracer.runtimeMetricTargetKeys, process)
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	assert.NotContains(t, tracer.goProcessAdmissions, process)
}

func TestAllowPIDBlocksIndeterminateSamplerSetup(t *testing.T) {
	filter := &recordingServiceFilter{}
	samplerManager := &fakeSamplerLifecycleManager{
		blockClearsFallback: true,
		fallbackUnsafe:      true,
	}
	tracer := &Tracer{
		log:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:               filter,
		samplerManager:           samplerManager,
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{},
	}
	tracer.SetEventContext(ebpfcommon.NewEBPFEventContext())
	retryPaused := make(chan struct{}, 1)
	resumeRetry := make(chan struct{})
	tracer.goAutoSDKRestoreRetryPause = func() {
		retryPaused <- struct{}{}
		<-resumeRetry
	}
	defer func() {
		samplerManager.blockCleanupSafe = true
		close(resumeRetry)
		tracer.goAutoSDKRestoreRetryWG.Wait()
	}()

	fileInfo := exec.New(exec.Init{
		Pid:       123,
		StartTime: 10000000,
	})
	admitted := tracer.AllowPIDForProcess(123, 0, fileInfo)

	assert.False(t, admitted)
	assert.True(t, tracer.PIDAdmissionRetryPending(123, 0, fileInfo))
	assert.Zero(t, filter.allowed)
	assert.Equal(t, 1, filter.blocked)
	select {
	case <-retryPaused:
	case <-time.After(time.Second):
		t.Fatal("sampler cleanup retry did not pause")
	}
	process := runtimeMetricTargetKey{pid: 123, ns: 0}
	assert.Equal(
		t,
		goProcessAdmissionState{
			startTime: fileInfo.StartTime(),
			fileInfo:  fileInfo,
		},
		tracer.goProcessAdmissions[process],
	)
	assert.Contains(t, tracer.goAutoSDKQuiescing, process)
	assert.NotEmpty(t, tracer.goAutoSDKRestoreRetries)
	assert.Empty(t, tracer.goProcessGenerationByPID)

	samplerManager.blockCleanupSafe = true
	close(resumeRetry)
	tracer.goAutoSDKRestoreRetryWG.Wait()
	resumeRetry = make(chan struct{})

	assert.NotContains(t, tracer.goProcessAdmissions, process)
	assert.NotContains(t, tracer.goAutoSDKQuiescing, process)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.True(t, tracer.PIDAdmissionRetryPending(123, 0, fileInfo),
		"background restoration must not consume attacher replay debt")
	assert.False(t, tracer.ExecutableUnlinkReady(fileInfo))

	require.True(t, tracer.AllowPIDForProcess(123, 0, fileInfo))
	assert.False(t, tracer.PIDAdmissionRetryPending(123, 0, fileInfo))
}

func TestPIDAdmissionRetryCancellationIsExactAndPreservesCleanupDebt(t *testing.T) {
	fileInfo := exec.New(exec.Init{
		Pid:       123,
		Ns:        7,
		StartTime: 10000000,
		Dev:       41,
		Ino:       73,
	})
	replacement := exec.New(exec.Init{
		Pid:       fileInfo.Pid(),
		Ns:        fileInfo.Ns(),
		StartTime: fileInfo.StartTime(),
		Dev:       fileInfo.Dev(),
		Ino:       fileInfo.Ino(),
	})
	process := runtimeMetricTargetKey{pid: fileInfo.Pid(), ns: fileInfo.Ns()}
	retry := goProcessAdmissionRetryKey{
		process:   process,
		startTime: fileInfo.StartTime(),
		fileInfo:  fileInfo,
	}
	restore := goAutoSDKRestoreRetryKey{
		process:   process,
		startTime: fileInfo.StartTime(),
		fileInfo:  fileInfo,
	}
	tracer := &Tracer{
		goProcessAdmissionRetries: map[goProcessAdmissionRetryKey]struct{}{
			retry: {},
		},
		goAutoSDKRestoreRetries: map[goAutoSDKRestoreRetryKey]bool{
			restore: true,
		},
	}

	assert.True(t, tracer.PIDAdmissionRetryPending(
		process.pid, process.ns, fileInfo,
	))
	assert.False(t, tracer.PIDAdmissionRetryPending(
		process.pid, process.ns+1, fileInfo,
	))
	assert.False(t, tracer.PIDAdmissionRetryPending(
		process.pid, process.ns, replacement,
	))
	assert.False(t, tracer.ExecutableUnlinkReady(fileInfo))
	assert.True(t, tracer.ExecutableUnlinkReady(exec.New(exec.Init{
		Dev: fileInfo.Dev() + 1,
		Ino: fileInfo.Ino(),
	})))

	tracer.CancelPIDAdmissionRetry(process.pid, process.ns, replacement)
	assert.True(t, tracer.PIDAdmissionRetryPending(
		process.pid, process.ns, fileInfo,
	))
	tracer.CancelPIDAdmissionRetry(process.pid, process.ns, fileInfo)
	tracer.CancelPIDAdmissionRetry(process.pid, process.ns, fileInfo)
	assert.False(t, tracer.PIDAdmissionRetryPending(
		process.pid, process.ns, fileInfo,
	))
	assert.False(t, tracer.ExecutableUnlinkReady(fileInfo),
		"canceling replay must leave restoration debt authoritative")

	delete(tracer.goAutoSDKRestoreRetries, restore)
	assert.True(t, tracer.ExecutableUnlinkReady(fileInfo))
}

func TestAllowPIDKeepsFallbackAfterSamplerCleanupRetry(t *testing.T) {
	filter := &recordingServiceFilter{}
	samplerManager := &fakeSamplerLifecycleManager{
		blockCleanupSafe:    true,
		blockClearsFallback: true,
		fallbackUnsafe:      true,
	}
	tracer := &Tracer{
		log:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:               filter,
		samplerManager:           samplerManager,
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{},
	}
	tracer.SetEventContext(ebpfcommon.NewEBPFEventContext())

	admitted := tracer.AllowPIDForProcess(123, 0, exec.New(exec.Init{
		Pid:       123,
		StartTime: 10000000,
	}))

	assert.True(t, admitted)
	assert.Equal(t, 1, filter.allowed)
	assert.Zero(t, filter.blocked)
	assert.Equal(t, 1, samplerManager.blockCalls)
}

func TestGoProcessCleanupWaitsForFallbackSafety(t *testing.T) {
	const startTime = uint64(10000000)
	process := runtimeMetricTargetKey{pid: 123, ns: 7}
	fileInfo := exec.New(exec.Init{
		Pid:       process.pid,
		Ns:        process.ns,
		StartTime: startTime,
	})
	filter := &recordingServiceFilter{}
	sampler := &fakeSamplerLifecycleManager{
		blockCleanupSafe: true,
		fallbackUnsafe:   true,
	}
	tracer := &Tracer{
		log:                slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:         filter,
		samplerManager:     sampler,
		goAutoSDKQuiescing: map[runtimeMetricTargetKey]bool{},
		goProcessAdmissions: map[runtimeMetricTargetKey]goProcessAdmissionState{
			process: {startTime: startTime, fileInfo: fileInfo},
		},
	}
	retryPaused := make(chan struct{}, 1)
	resumeRetry := make(chan struct{})
	var resumeOnce sync.Once
	tracer.goAutoSDKRestoreRetryPause = func() {
		retryPaused <- struct{}{}
		<-resumeRetry
	}
	defer func() {
		sampler.fallbackUnsafe = false
		resumeOnce.Do(func() { close(resumeRetry) })
		tracer.goAutoSDKRestoreRetryWG.Wait()
	}()

	tracer.BlockPIDForProcess(process.pid, process.ns, fileInfo)
	select {
	case <-retryPaused:
	case <-time.After(time.Second):
		t.Fatal("sampler cleanup retry did not pause")
	}
	assert.Contains(t, tracer.goProcessAdmissions, process)
	assert.Contains(t, tracer.goAutoSDKQuiescing, process)
	assert.NotEmpty(t, tracer.goAutoSDKRestoreRetries)

	sampler.fallbackUnsafe = false
	resumeOnce.Do(func() { close(resumeRetry) })
	tracer.goAutoSDKRestoreRetryWG.Wait()

	assert.NotContains(t, tracer.goProcessAdmissions, process)
	assert.NotContains(t, tracer.goAutoSDKQuiescing, process)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.NotEmpty(t, sampler.blockStartTimes)
	for _, cleanedStartTime := range sampler.blockStartTimes {
		assert.Equal(t, startTime, cleanedStartTime)
	}
}

func TestGoProcessCleanupUsesCurrentAdmissionBeforeRetainedGeneration(t *testing.T) {
	const (
		startTime = uint64(10000000)
		hostPID   = uint32(1001)
	)
	process := runtimeMetricTargetKey{pid: 123, ns: 7}
	oldFileInfo := exec.New(exec.Init{
		Pid:       process.pid,
		Ns:        process.ns,
		StartTime: startTime,
	})
	newFileInfo := exec.New(exec.Init{
		Pid:       process.pid,
		Ns:        process.ns,
		StartTime: startTime,
	})
	optionKey := goSpanOptionFunctionKey{
		HostPID:    uint64(hostPID),
		Generation: 11,
		Function:   99,
	}
	typeInfoKey := goProcessKey{PID: uint64(hostPID), Generation: 11}
	optionMap := &fakeGoSpanOptionMap{
		values: map[goSpanOptionFunctionKey]uint8{optionKey: goSpanOptionKind},
	}
	typeInfoMap := &fakeGoAutoSDKTypeInfoMap{
		values: map[goProcessKey]BpfGoAutoSdkTypeInfoT{typeInfoKey: {}},
	}
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			hostPID: {Generation: 11, StartTime: startTime},
		},
	}
	sampler := &fakeSamplerLifecycleManager{blockCleanupSafe: true}
	filter := &recordingServiceFilter{}
	tracer := &Tracer{
		log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:            filter,
		samplerManager:        sampler,
		goSpanOptionFunctions: optionMap,
		goAutoSDKTypeInfos:    typeInfoMap,
		goProcessGenerations:  generationMap,
		goAutoSDKQuiescing:    map[runtimeMetricTargetKey]bool{},
		goSpanOptionKeysByProcess: map[runtimeMetricTargetKey][]goSpanOptionFunctionKey{
			process: {optionKey},
		},
		goAutoSDKTypeInfoKeys: map[runtimeMetricTargetKey]goProcessKey{
			process: typeInfoKey,
		},
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{
			process: {
				hostPID:    hostPID,
				generation: 11,
				fileInfo:   oldFileInfo,
				retired:    true,
			},
		},
		goProcessOwnerByHostPID: map[uint32]runtimeMetricTargetKey{hostPID: process},
		goProcessAdmissions: map[runtimeMetricTargetKey]goProcessAdmissionState{
			process: {
				startTime:       startTime,
				generationReady: false,
				fileInfo:        newFileInfo,
			},
		},
		goAutoSDKAdmissions: map[runtimeMetricTargetKey]goAutoSDKAdmissionState{
			process: {
				startTime: startTime,
				fileInfo:  newFileInfo,
			},
		},
	}

	tracer.BlockPIDForProcess(process.pid, process.ns, oldFileInfo)

	assert.Zero(t, filter.blocked)
	assert.Empty(t, sampler.blockStartTimes)
	assert.Same(t, newFileInfo, tracer.goProcessAdmissions[process].fileInfo)
	assert.Contains(t, tracer.goProcessGenerationByPID, process)
	assert.Contains(t, generationMap.values, hostPID)

	tracer.BlockPIDForProcess(process.pid, process.ns, newFileInfo)

	assert.Equal(t, []uint64{startTime}, sampler.blockStartTimes)
	assert.NotContains(t, tracer.goProcessAdmissions, process)
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
	assert.NotContains(t, tracer.goProcessOwnerByHostPID, hostPID)
	assert.Empty(t, generationMap.values)
	assert.Empty(t, optionMap.values)
	assert.Empty(t, typeInfoMap.values)
}

func TestGoProcessRetryCannotCleanReplacementWithSameKey(t *testing.T) {
	const hostPID = uint32(456)
	process := runtimeMetricTargetKey{pid: 123, ns: 7}
	filter := &recordingServiceFilter{}
	sampler := &fakeSamplerLifecycleManager{}
	generationMap := &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{},
	}
	generations := []uint64{11, 22}
	nextGeneration := 0
	tracer := &Tracer{
		log:                           slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:                    filter,
		samplerManager:                sampler,
		goProcessGenerations:          generationMap,
		goProcessGenerationByPID:      map[runtimeMetricTargetKey]goProcessGenerationState{},
		goProcessOwnerByHostPID:       map[uint32]runtimeMetricTargetKey{},
		goProcessAdmissions:           map[runtimeMetricTargetKey]goProcessAdmissionState{},
		goAutoSDKAdmissions:           map[runtimeMetricTargetKey]goAutoSDKAdmissionState{},
		goAutoSDKQuiescing:            map[runtimeMetricTargetKey]bool{},
		goSpanOptionFuncsByExecutable: map[goExecutableKey][]goSpanOptionFunction{},
		goSpanOptionKeysByProcess:     map[runtimeMetricTargetKey][]goSpanOptionFunctionKey{},
		goAutoSDKTypesByExecutable:    map[goExecutableKey]goexec.GoAutoSDKTypeInfo{},
		goAutoSDKTypeInfoKeys:         map[runtimeMetricTargetKey]goProcessKey{},
		newGoProcessGeneration: func() (uint64, error) {
			generation := generations[nextGeneration]
			nextGeneration++
			return generation, nil
		},
		resolveGoProcessHostPID: func(app.PID, uint32) (uint32, error) {
			return hostPID, nil
		},
	}
	tracer.SetEventContext(ebpfcommon.NewEBPFEventContext())
	retryPaused := make(chan struct{}, 1)
	resumeRetry := make(chan struct{})
	var resumeOnce sync.Once
	tracer.goAutoSDKRestoreRetryPause = func() {
		retryPaused <- struct{}{}
		<-resumeRetry
	}
	defer func() {
		sampler.blockCleanupSafe = true
		resumeOnce.Do(func() { close(resumeRetry) })
		tracer.goAutoSDKRestoreRetryWG.Wait()
	}()

	first := exec.New(exec.Init{
		Pid:       process.pid,
		Ns:        process.ns,
		StartTime: 10000000,
	})
	require.True(t, tracer.AllowPIDForProcess(process.pid, process.ns, first))
	tracer.BlockPIDForProcess(process.pid, process.ns, first)
	select {
	case <-retryPaused:
	case <-time.After(time.Second):
		t.Fatal("old-incarnation cleanup retry did not pause")
	}

	sampler.blockCleanupSafe = true
	second := exec.New(exec.Init{
		Pid:       process.pid,
		Ns:        process.ns,
		StartTime: first.StartTime(),
	})
	require.True(t, tracer.AllowPIDForProcess(process.pid, process.ns, second))
	state := tracer.goProcessGenerationByPID[process]
	require.NotNil(t, state.fileInfo)
	assert.Same(t, second, state.fileInfo)
	assert.Equal(t, uint64(22), state.generation)
	assert.Equal(t, second.StartTime(), tracer.goProcessAdmissions[process].startTime)

	resumeOnce.Do(func() { close(resumeRetry) })
	tracer.goAutoSDKRestoreRetryWG.Wait()

	state = tracer.goProcessGenerationByPID[process]
	require.NotNil(t, state.fileInfo)
	assert.Same(t, second, state.fileInfo)
	assert.Equal(t, uint64(22), state.generation)
	assert.Equal(t, second.StartTime(), generationMap.values[hostPID].StartTime)
	assert.Equal(t, uint64(22), generationMap.values[hostPID].Generation)
	assert.Equal(t, second.StartTime(), tracer.goProcessAdmissions[process].startTime)
	assert.NotContains(t, tracer.goAutoSDKQuiescing, process)
}

type fakeGoAutoSDKTypeInfoMap struct {
	values    map[goProcessKey]BpfGoAutoSdkTypeInfoT
	putErr    error
	deleteErr error
}

func (m *fakeGoAutoSDKTypeInfoMap) Put(key, value any) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.values[key.(goProcessKey)] = value.(BpfGoAutoSdkTypeInfoT)
	return nil
}

func (m *fakeGoAutoSDKTypeInfoMap) Delete(key any) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	processKey := key.(goProcessKey)
	if _, ok := m.values[processKey]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.values, processKey)
	return nil
}

func TestGoAutoSDKTypeInfoRegistrationDoesNotRequireActivation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	const ino = uint64(73)
	pid := app.PID(os.Getpid())
	typeInfo := validGoAutoSDKTypeInfo()
	typeInfo.AttributeOptionType = 0x300
	typeInfo.TimestampOptionType = 0x400
	typeInfoMap := &fakeGoAutoSDKTypeInfoMap{
		values: map[goProcessKey]BpfGoAutoSdkTypeInfoT{},
	}
	fileInfo := exec.New(exec.Init{Ino: ino, Pid: pid})
	pidInfo, err := runtimeMetricPIDInfo(pid, 0)
	require.NoError(t, err)
	process := runtimeMetricTargetKey{pid: pid, ns: 0}
	processKey := goProcessKey{PID: uint64(pidInfo.HostPid), Generation: 17}
	tracer := &Tracer{
		log:                           slog.New(slog.NewTextHandler(io.Discard, nil)),
		goAutoSDKEligibleByExecutable: map[goExecutableKey]bool{testGoExecutableKey(ino): false},
		goAutoSDKReadyByExecutable:    map[goExecutableKey]bool{testGoExecutableKey(ino): false},
		goAutoSDKTypesByExecutable:    map[goExecutableKey]goexec.GoAutoSDKTypeInfo{testGoExecutableKey(ino): typeInfo},
		goAutoSDKTypeInfos:            typeInfoMap,
		goAutoSDKTypeInfoKeys:         map[runtimeMetricTargetKey]goProcessKey{},
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{
			process: {
				hostPID:    pidInfo.HostPid,
				generation: processKey.Generation,
				fileInfo:   fileInfo,
			},
		},
		goProcessOwnerByHostPID: map[uint32]runtimeMetricTargetKey{
			pidInfo.HostPid: process,
		},
	}

	require.True(t, tracer.registerGoAutoSDKTypeInfo(pid, 0, fileInfo))
	assert.Contains(t, typeInfoMap.values, processKey)
	assert.False(t, tracer.goAutoSDKEligibleByExecutable[testGoExecutableKey(ino)])
	assert.False(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)])

	tracer.deleteGoAutoSDKTypeInfo(pid, 0)
	assert.NotContains(t, typeInfoMap.values, processKey)
	assert.NotContains(t, tracer.goAutoSDKTypeInfoKeys, process)
}

func TestRelocateGoAutoSDKTypeInfo(t *testing.T) {
	typeInfo := validGoAutoSDKTypeInfo()
	typeInfo.AttributeOptionType = 0x300
	typeInfo.TimestampOptionType = 0x400

	relocated, err := relocateGoAutoSDKTypeInfo(typeInfo, 0x1000)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x1100), relocated.TraceContextKeyType)
	assert.Equal(t, uint64(0x1200), relocated.NonRecordingSpanType)
	assert.Equal(t, uint64(0x1500), relocated.RecordingSpanType)
	assert.Equal(t, uint64(0x1300), relocated.AttributeOptionType)
	assert.Equal(t, uint64(0x1400), relocated.TimestampOptionType)
	assert.Equal(t, typeInfo.NonRecordingSpanContextPos, relocated.NonRecordingSpanContextPos)
	assert.Equal(t, typeInfo.RecordingSpanContextPos, relocated.RecordingSpanContextPos)
	assert.Equal(t, typeInfo.SpanContextTraceIDPos, relocated.SpanContextTraceIdPos)
	assert.Equal(t, typeInfo.SpanContextSpanIDPos, relocated.SpanContextSpanIdPos)
	assert.Equal(t, typeInfo.SpanContextTraceFlagsPos, relocated.SpanContextTraceFlagsPos)
	assert.Equal(t, typeInfo.SpanContextRemotePos, relocated.SpanContextRemotePos)

	typeInfo.NonRecordingSpanType = 0
	relocated, err = relocateGoAutoSDKTypeInfo(typeInfo, 0x1000)
	require.NoError(t, err)
	assert.Zero(t, relocated.NonRecordingSpanType)

	typeInfo.TraceContextKeyType = ^uint64(0)
	_, err = relocateGoAutoSDKTypeInfo(typeInfo, 1)
	require.Error(t, err)

	typeInfo = validGoAutoSDKTypeInfo()
	typeInfo.TimestampOptionType = ^uint64(0)
	_, err = relocateGoAutoSDKTypeInfo(typeInfo, 1)
	require.Error(t, err)
}

func TestGoSpanOptionFunctionRegistrationLifecycle(t *testing.T) {
	const ino = uint64(99)
	pid := app.PID(os.Getpid())
	functionMap := &fakeGoSpanOptionMap{
		values: map[goSpanOptionFunctionKey]uint8{},
	}
	tracer := &Tracer{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		goSpanOptionFuncsByExecutable: map[goExecutableKey][]goSpanOptionFunction{
			testGoExecutableKey(ino): {
				{entry: 0x100, optionType: goSpanOptionKind},
				{entry: 0x200, optionType: goSpanOptionNewRoot},
			},
		},
		goSpanOptionKeysByProcess: map[runtimeMetricTargetKey][]goSpanOptionFunctionKey{},
		goSpanOptionFunctions:     functionMap,
	}
	fileInfo := exec.New(exec.Init{Ino: ino, Pid: pid})
	pidInfo, err := runtimeMetricPIDInfo(pid, 0)
	require.NoError(t, err)
	process := runtimeMetricTargetKey{pid: pid, ns: 0}
	tracer.goProcessGenerationByPID = map[runtimeMetricTargetKey]goProcessGenerationState{
		process: {
			hostPID:    pidInfo.HostPid,
			generation: 19,
			fileInfo:   fileInfo,
		},
	}
	tracer.goProcessOwnerByHostPID = map[uint32]runtimeMetricTargetKey{
		pidInfo.HostPid: process,
	}

	require.True(t, tracer.registerGoSpanOptionFunctions(pid, 0, fileInfo))
	require.Len(t, functionMap.values, 2)
	optionTypes := map[uint8]int{}
	for _, optionType := range functionMap.values {
		optionTypes[optionType]++
	}
	assert.Equal(t, map[uint8]int{
		goSpanOptionKind:    1,
		goSpanOptionNewRoot: 1,
	}, optionTypes)

	require.True(t, tracer.registerGoSpanOptionFunctions(pid, 0, fileInfo))
	assert.Equal(t, 4, functionMap.putCalls)
	assert.Zero(t, functionMap.deleteCalls)

	tracer.deleteGoSpanOptionFunctions(pid, 0)
	assert.Empty(t, functionMap.values)
	assert.NotContains(t, tracer.goSpanOptionKeysByProcess, process)
}

func TestGoRuntimeMetricAvailability(t *testing.T) {
	baseOffsets := &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.RuntimeMemstatsNumGCPos:         uint64(0),
		goexec.RuntimeGCControllerGCPercentPos: uint64(8),
	}}

	mask := goRuntimeMetricMask(baseOffsets)
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.NotZero(t, mask&goRuntimeMetricGCCyclesMask)
	assert.Zero(t, mask&goRuntimeMetricMemoryLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricProcessorLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricGOGCMask)
	assert.Zero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Zero(t, mask&goRuntimeMetricMemoryUsedMask)
	assert.Zero(t, mask&goRuntimeMetricMemoryAllocsMask)

	baseOffsets.Field[goexec.RuntimeGCControllerMemoryLimitPos] = uint64(16)
	assert.NotZero(t, goRuntimeMetricMask(baseOffsets)&goRuntimeMetricMemoryLimitMask)

	for _, field := range goRuntimeCPUTimeOffsetFields {
		baseOffsets.Field[field] = uint64(field)
	}
	assert.NotZero(t, goRuntimeMetricMask(baseOffsets)&goRuntimeMetricCPUTimeMask)

	delete(baseOffsets.Field, goRuntimeCPUTimeOffsetFields[0])
	assert.Zero(t, goRuntimeMetricMask(baseOffsets)&goRuntimeMetricCPUTimeMask)

	for _, field := range goRuntimeMemoryOffsetFields {
		baseOffsets.Field[field] = uint64(field)
	}
	memoryMask := goRuntimeMetricMask(baseOffsets)
	assert.NotZero(t, memoryMask&goRuntimeMetricMemoryUsedMask)
	assert.NotZero(t, memoryMask&goRuntimeMetricMemoryAllocsMask)

	delete(baseOffsets.Field, goRuntimeMemoryOffsetFields[0])
	memoryMask = goRuntimeMetricMask(baseOffsets)
	assert.Zero(t, memoryMask&goRuntimeMetricMemoryUsedMask)
	assert.Zero(t, memoryMask&goRuntimeMetricMemoryAllocsMask)

	delete(baseOffsets.Field, goexec.RuntimeMemstatsNumGCPos)
	assert.False(t, hasBaseGoRuntimeMetrics(goRuntimeMetricMask(baseOffsets)))
}

func TestGoRuntimeHistogramAvailabilityRequiresSupportedLayout(t *testing.T) {
	offsets := &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.RuntimeTimeHistogramUnderflowPos: uint64(1280),
		goexec.RuntimeTimeHistogramOverflowPos:  uint64(1288),
	}}

	mask := goRuntimeMetricMask(offsets)
	assert.Zero(t, mask&goRuntimeMetricGCPauseHistogramMask)
	assert.Zero(t, mask&goRuntimeMetricScheduleDurationHistogramMask)

	offsets.Field[goexec.RuntimeSchedTimeToRunPos] = uint64(640)
	mask = goRuntimeMetricMask(offsets)
	assert.Zero(t, mask&goRuntimeMetricGCPauseHistogramMask)
	assert.NotZero(t, mask&goRuntimeMetricScheduleDurationHistogramMask)

	offsets.Field[goexec.RuntimeSchedSTWTotalTimeGCPos] = uint64(4520)
	mask = goRuntimeMetricMask(offsets)
	assert.NotZero(t, mask&goRuntimeMetricGCPauseHistogramMask)
	assert.NotZero(t, mask&goRuntimeMetricScheduleDurationHistogramMask)

	delete(offsets.Field, goexec.RuntimeTimeHistogramUnderflowPos)
	mask = goRuntimeMetricMask(offsets)
	assert.Zero(t, mask&goRuntimeMetricGCPauseHistogramMask)
	assert.Zero(t, mask&goRuntimeMetricScheduleDurationHistogramMask)
}

func TestGoRuntimeHistogramAvailabilityRejectsUnsupportedLayout(t *testing.T) {
	const supportedBucketCount = 160
	const bucketSize = uint64(8)

	offsets := &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.RuntimeMemstatsNumGCPos:          uint64(0),
		goexec.RuntimeGCControllerGCPercentPos:  uint64(8),
		goexec.RuntimeSchedTimeToRunPos:         uint64(320),
		goexec.RuntimeSchedSTWTotalTimeGCPos:    uint64(4224),
		goexec.RuntimeTimeHistogramUnderflowPos: uint64(supportedBucketCount-1) * bucketSize,
		goexec.RuntimeTimeHistogramOverflowPos:  uint64(supportedBucketCount) * bucketSize,
	}}

	mask := goRuntimeMetricMask(offsets)
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.Zero(t, mask&goRuntimeMetricHistogramMask)

	offsets.Field[goexec.RuntimeTimeHistogramUnderflowPos] = uint64(supportedBucketCount) * bucketSize
	mask = goRuntimeMetricMask(offsets)
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.Zero(t, mask&goRuntimeMetricHistogramMask)

	offsets.Field[goexec.RuntimeTimeHistogramOverflowPos] = uint64(supportedBucketCount+1) * bucketSize

	mask = goRuntimeMetricMask(offsets)
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.Equal(t, goRuntimeMetricHistogramMask, mask&goRuntimeMetricHistogramMask)
}

func TestGoRuntimeMetricMaskABI(t *testing.T) {
	assert.Equal(t, goRuntimeMetricGCCyclesMask, uint64(1<<0))
	assert.Equal(t, goRuntimeMetricMemoryLimitMask, uint64(1<<1))
	assert.Equal(t, goRuntimeMetricProcessorLimitMask, uint64(1<<2))
	assert.Equal(t, goRuntimeMetricGOGCMask, uint64(1<<3))
	assert.Equal(t, goRuntimeMetricCPUTimeMask, uint64(1<<4))
	assert.Equal(t, goRuntimeMetricMemoryUsedMask, uint64(1<<5))
	assert.Equal(t, goRuntimeMetricMemoryAllocsMask, uint64(1<<6))
	assert.Equal(t, goRuntimeMetricGCPauseHistogramMask, uint64(1<<7))
	assert.Equal(t, goRuntimeMetricScheduleDurationHistogramMask, uint64(1<<8))
	assert.Equal(t, goRuntimeMetricGoroutineCountMask, uint64(1<<9))
	assert.Equal(t, goRuntimeMetricMemoryGCGoalMask, uint64(1<<10))
}

func TestGoRuntimeMetricTargetABIAppendsGoroutineMetadata(t *testing.T) {
	var target BpfGoRuntimeMetricTargetT

	assert.Equal(t, uintptr(104), unsafe.Sizeof(target))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(target.SizeClassToSizesAddr))
	assert.Equal(t, uintptr(48), unsafe.Offsetof(target.SchedAddr))
	assert.Equal(t, uintptr(56), unsafe.Offsetof(target.AllglenAddr))
	assert.Equal(t, uintptr(64), unsafe.Offsetof(target.AllpAddr))
	assert.Equal(t, uintptr(72), unsafe.Offsetof(target.GoroutineCountIncludesSystem))
}

func TestGoRuntimeMetricTargetABIAppendsGCGoalCache(t *testing.T) {
	var target BpfGoRuntimeMetricTargetT

	assert.Equal(t, uintptr(104), unsafe.Sizeof(target))
	assert.Equal(t, uintptr(80), unsafe.Offsetof(target.GcGoalSource))
	assert.Equal(t, uintptr(88), unsafe.Offsetof(target.GcGoal))
	assert.Equal(t, uintptr(96), unsafe.Offsetof(target.Generation))
}

func TestGoRuntimeGCGoalSourceSelection(t *testing.T) {
	tests := []struct {
		name                  string
		offsets               *goexec.Offsets
		goalArgumentSupported bool
		want                  goRuntimeGCGoalSource
	}{
		{name: "missing metadata", offsets: nil, want: goRuntimeGCGoalSourceNone},
		{name: "probe symbol with compatible signature", offsets: &goexec.Offsets{Funcs: map[string]goexec.FuncOffsets{
			goRuntimeMetricGCGoalSymbol: {},
		}}, goalArgumentSupported: true, want: goRuntimeGCGoalSourcePaceScavengerArgument},
		{name: "probe symbol with incompatible signature", offsets: &goexec.Offsets{Funcs: map[string]goexec.FuncOffsets{
			goRuntimeMetricGCGoalSymbol: {},
		}}, want: goRuntimeGCGoalSourceNone},
		{name: "heap goal field preferred when both sources are present", offsets: &goexec.Offsets{
			Funcs: map[string]goexec.FuncOffsets{goRuntimeMetricGCGoalSymbol: {}},
			Field: goexec.FieldOffsets{goexec.RuntimeGCControllerHeapGoalPos: uint64(112)},
		}, want: goRuntimeGCGoalSourceHeapGoalField},
		{name: "sources missing", offsets: &goexec.Offsets{}, want: goRuntimeGCGoalSourceNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, selectGoRuntimeGCGoalSource(tt.offsets, tt.goalArgumentSupported))
		})
	}
}

func TestGoRuntimeGCGoalProbeAttachedOnlyForPaceScavengerSource(t *testing.T) {
	disableContextPropagationForTest(t)
	tracer := &Tracer{
		currentBinaryExecutable: testGoExecutableKey(1),
		goRuntimeMetricMaskByExecutable: map[goExecutableKey]uint64{
			testGoExecutableKey(1): goRuntimeMetricBaseMask | goRuntimeMetricMemoryGCGoalMask,
		},
		goRuntimeGCGoalSourceByExecutable: map[goExecutableKey]goRuntimeGCGoalSource{
			testGoExecutableKey(1): goRuntimeGCGoalSourcePaceScavengerArgument,
			testGoExecutableKey(2): goRuntimeGCGoalSourceHeapGoalField,
			testGoExecutableKey(3): goRuntimeGCGoalSourceNone,
		},
	}
	tracer.bpfObjects.ObiUprobeGoRuntimeGcGoal = &ebpf.Program{}

	probes := tracer.GoProbes()
	require.Contains(t, probes, goRuntimeMetricGCGoalSymbol)
	require.NotNil(t, probes[goRuntimeMetricGCGoalSymbol][0].Start)
	assert.Contains(t, probes, goRuntimeMetricGCMarkDoneSymbol)

	for _, ino := range []uint64{2, 3} {
		tracer.currentBinaryExecutable = testGoExecutableKey(ino)
		probes = tracer.GoProbes()
		assert.NotContains(t, probes, goRuntimeMetricGCGoalSymbol)
		assert.Contains(t, probes, goRuntimeMetricGCMarkDoneSymbol)
	}
}

func TestGoRuntimeGoroutineCountAvailabilityRequiresAllOffsets(t *testing.T) {
	offsets := goRuntimeMetricOffsets()
	delete(offsets.Field, goexec.RuntimeGListSizePos)

	assert.False(t, hasGoRuntimeGoroutineCountOffsets(offsets, false, true))
	assert.False(t, hasGoRuntimeGoroutineCountOffsets(offsets, true, true))
}

func TestGoRuntimeGoroutineCountAvailabilityRequiresNgsysOnlyBeforeGo126(t *testing.T) {
	offsets := goRuntimeMetricOffsets()
	delete(offsets.Field, goexec.RuntimeSchedNgSysPos)

	assert.False(t, hasGoRuntimeGoroutineCountOffsets(offsets, false, false), "unknown mode must fail closed")
	assert.False(t, hasGoRuntimeGoroutineCountOffsets(offsets, false, true), "Go 1.25 requires sched.ngsys")
	assert.True(t, hasGoRuntimeGoroutineCountOffsets(offsets, true, true), "Go 1.26 does not read sched.ngsys")

	offsets.Field[goexec.RuntimeSchedNgSysPos] = uint64(0)
	assert.True(t, hasGoRuntimeGoroutineCountOffsets(offsets, false, true))
}

func TestGoRuntimeMetricsUseHeapSnapshotProbe(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		currentBinaryExecutable: testGoExecutableKey(1),
		goRuntimeMetricMaskByExecutable: map[goExecutableKey]uint64{
			testGoExecutableKey(1): goRuntimeMetricBaseMask,
			testGoExecutableKey(2): goRuntimeMetricBaseMask | goRuntimeMetricCPUTimeMask,
			testGoExecutableKey(3): goRuntimeMetricBaseMask | goRuntimeMetricMemoryUsedMask,
		},
	}

	probes := tracer.GoProbes()
	require.Contains(t, probes, "runtime.gcMarkDone")
	assert.NotContains(t, probes, "runtime.(*scavengeIndex).nextGen")

	tracer.currentBinaryExecutable = testGoExecutableKey(2)
	probes = tracer.GoProbes()
	require.Contains(t, probes, "runtime.gcMarkDone")
	assert.NotContains(t, probes, "runtime.(*scavengeIndex).nextGen")

	tracer.currentBinaryExecutable = testGoExecutableKey(3)
	probes = tracer.GoProbes()
	require.Contains(t, probes, "runtime.(*scavengeIndex).nextGen")
	assert.NotContains(t, probes, "runtime.gcMarkDone")
}

func TestGoProbesWaitsForCoherentProcessState(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		currentBinaryExecutable: testGoExecutableKey(1),
		goChannelOffsetsByExecutable: map[goExecutableKey]bool{
			testGoExecutableKey(1): false,
			testGoExecutableKey(2): true,
		},
		goRuntimeMetricMaskByExecutable: map[goExecutableKey]uint64{
			testGoExecutableKey(1): goRuntimeMetricBaseMask,
			testGoExecutableKey(2): goRuntimeMetricBaseMask | goRuntimeMetricHeapSnapshotMask,
		},
	}
	tracer.processMu.Lock()
	started := make(chan struct{})
	probesResult := make(chan map[string][]*ebpfcommon.ProbeDesc)
	go func() {
		close(started)
		probesResult <- tracer.GoProbes()
	}()
	<-started
	select {
	case <-probesResult:
		tracer.processMu.Unlock()
		t.Fatal("Go probe selection bypassed process state serialization")
	case <-time.After(50 * time.Millisecond):
	}

	tracer.currentBinaryExecutable = testGoExecutableKey(2)
	tracer.processMu.Unlock()
	probes := <-probesResult

	require.Contains(t, probes, goRuntimeMetricProbeSymbols[1])
	assert.NotContains(t, probes, goRuntimeMetricProbeSymbols[0])
	for _, symbol := range goChannelLinkProbeSymbols {
		assert.Contains(t, probes, symbol)
	}
}

func TestGoProbeStateConcurrentUpdates(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		currentBinaryExecutable: testGoExecutableKey(1),
		goChannelOffsetsByExecutable: map[goExecutableKey]bool{
			testGoExecutableKey(1): true,
			testGoExecutableKey(2): false,
		},
		goRuntimeMetricMaskByExecutable: map[goExecutableKey]uint64{
			testGoExecutableKey(1): goRuntimeMetricBaseMask,
		},
	}
	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			ino := uint64(i%2 + 1)
			tracer.processMu.Lock()
			tracer.currentBinaryExecutable = testGoExecutableKey(ino)
			tracer.goChannelOffsetsByExecutable[testGoExecutableKey(ino)] = i%2 == 0
			tracer.goRuntimeMetricMaskByExecutable[testGoExecutableKey(ino)] = goRuntimeMetricBaseMask |
				uint64(i%2)*goRuntimeMetricHeapSnapshotMask
			tracer.processMu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			tracer.GoProbes()
		}
	}()
	wg.Wait()
}

func TestGoRuntimeMetricsFallBackWhenHeapProbeIsMissing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	disableContextPropagationForTest(t)

	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{
		ELF:        currentExecutableELF(t),
		Ino:        1,
		Pid:        123,
		CmdExePath: "/test/server",
	})
	offsets := goRuntimeMetricOffsets()

	tracer.recordGoRuntimeMetricAvailability(fileInfo, offsets)
	tracer.ProcessBinary(fileInfo)

	mask := tracer.goRuntimeMetricMaskByExecutable[testGoExecutableKeyFor(fileInfo)]
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.NotZero(t, mask&goRuntimeMetricMemoryLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricProcessorLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Zero(t, mask&goRuntimeMetricHeapSnapshotMask)

	probes := tracer.GoProbes()
	require.Contains(t, probes, goRuntimeMetricProbeSymbols[0])
	assert.NotContains(t, probes, goRuntimeMetricProbeSymbols[1])
	assert.Contains(t, logs.String(), "Go runtime heap metric symbol unresolved; using scalar fallback")
}

func TestGoRuntimeMetricsUseResolvedHeapProbe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	disableContextPropagationForTest(t)

	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(
		&logs,
		&slog.HandlerOptions{Level: slog.LevelDebug},
	))}
	fileInfo := exec.New(exec.Init{ELF: currentExecutableELF(t), Ino: 1})
	offsets := goRuntimeMetricOffsets()
	offsets.Funcs[goRuntimeMetricProbeSymbols[1]] = goexec.FuncOffsets{}

	tracer.recordGoRuntimeMetricAvailability(fileInfo, offsets)
	tracer.ProcessBinary(fileInfo)

	mask := tracer.goRuntimeMetricMaskByExecutable[testGoExecutableKeyFor(fileInfo)]
	assert.NotZero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Equal(t, goRuntimeMetricHeapSnapshotMask, mask&goRuntimeMetricHeapSnapshotMask)
	assert.NotZero(t, mask&goRuntimeMetricGoroutineCountMask)
	assert.NotZero(t, mask&goRuntimeMetricMemoryGCGoalMask)
	assert.Contains(t, logs.String(), "goroutine_count_available=true")

	probes := tracer.GoProbes()
	require.Contains(t, probes, goRuntimeMetricProbeSymbols[1])
	assert.NotContains(t, probes, goRuntimeMetricProbeSymbols[0])
}

func TestGoRuntimeMetricMaskRequiresSizeClassTableForAllocations(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1, Pid: 123, CmdExePath: "/test/server"})
	mask := goRuntimeMetricBaseMask |
		goRuntimeMetricCPUTimeMask |
		goRuntimeMetricMemoryUsedMask |
		goRuntimeMetricMemoryAllocsMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{})

	assert.Zero(t, got&goRuntimeMetricMemoryAllocsMask)
	assert.NotZero(t, got&goRuntimeMetricMemoryUsedMask)
	assert.NotZero(t, got&goRuntimeMetricCPUTimeMask)
	assert.True(t, hasBaseGoRuntimeMetrics(got))
	assert.Contains(t, logs.String(),
		"Go runtime size-class table symbol unresolved; disabling allocation metrics")
}

func TestGoRuntimeMetricMaskKeepsAllocationsWithSizeClassTable(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1})
	mask := goRuntimeMetricBaseMask | goRuntimeMetricMemoryAllocsMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{
		SizeClassToSizesAddr: 0x1234,
	})

	assert.Equal(t, mask, got)
	assert.Empty(t, logs.String())
}

func TestGoRuntimeMetricMaskRequiresGoroutineSymbolsAndModeOnlyForCount(t *testing.T) {
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1})
	mask := goRuntimeMetricBaseMask | goRuntimeMetricCPUTimeMask | goRuntimeMetricGoroutineCountMask
	symbols := goexec.RuntimeMetricSymbols{
		SchedAddr:               0x1000,
		AllgLenAddr:             0x2000,
		AllpAddr:                0x3000,
		GoroutineCountModeKnown: true,
	}

	assert.Equal(t, mask, tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, symbols))

	symbols.AllgLenAddr = 0
	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, symbols)
	assert.Zero(t, got&goRuntimeMetricGoroutineCountMask)
	assert.NotZero(t, got&goRuntimeMetricCPUTimeMask)

	symbols.AllgLenAddr = 0x2000
	symbols.GoroutineCountModeKnown = false
	got = tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, symbols)
	assert.Zero(t, got&goRuntimeMetricGoroutineCountMask)
	assert.NotZero(t, got&goRuntimeMetricCPUTimeMask)
}

func TestGoRuntimeMetricMaskRequiresSchedulerSymbolForHistograms(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1, Pid: 123, CmdExePath: "/test/server"})
	mask := goRuntimeMetricBaseMask |
		goRuntimeMetricCPUTimeMask |
		goRuntimeMetricGCPauseHistogramMask |
		goRuntimeMetricScheduleDurationHistogramMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{})

	assert.Zero(t, got&goRuntimeMetricHistogramMask)
	assert.NotZero(t, got&goRuntimeMetricCPUTimeMask)
	assert.True(t, hasBaseGoRuntimeMetrics(got))
	assert.Contains(t, logs.String(),
		"Go runtime scheduler symbol unresolved; disabling histogram metrics")
}

func TestGoRuntimeMetricMaskKeepsHistogramsWithSchedulerSymbol(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1})
	mask := goRuntimeMetricBaseMask | goRuntimeMetricHistogramMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{
		SchedAddr: 0x1234,
	})

	assert.Equal(t, mask, got)
	assert.Empty(t, logs.String())
}

func TestProcessBinarySelectsRecordedChannelOffsetState(t *testing.T) {
	tracer := &Tracer{
		goChannelOffsetsByExecutable: map[goExecutableKey]bool{
			testGoExecutableKey(1): true,
			testGoExecutableKey(2): false,
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
		goexec.HchanQcountPos:   uint64(0),
		goexec.HchanDataqsizPos: uint64(8),
		goexec.HchanSendxPos:    uint64(48),
		goexec.HchanRecvxPos:    uint64(56),
	}}
}

func validGoAutoSDKTypeInfo() goexec.GoAutoSDKTypeInfo {
	return goexec.GoAutoSDKTypeInfo{
		TraceContextKeyType:        0x100,
		NonRecordingSpanType:       0x200,
		RecordingSpanType:          0x500,
		NonRecordingSpanContextPos: 16,
		RecordingSpanContextPos:    96,
		SpanContextTraceIDPos:      0,
		SpanContextSpanIDPos:       16,
		SpanContextTraceFlagsPos:   24,
		SpanContextRemotePos:       56,
		Resolved:                   true,
	}
}

func goRuntimeMetricOffsets() *goexec.Offsets {
	offsets := &goexec.Offsets{
		Funcs: map[string]goexec.FuncOffsets{
			goRuntimeMetricProbeSymbols[0]: {},
		},
		Field: goexec.FieldOffsets{},
	}
	for _, field := range goRuntimeMetricOffsetFields {
		offsets.Field[field] = uint64(field)
	}
	return offsets
}

func currentExecutableELF(t *testing.T) *elf.File {
	t.Helper()

	executable, err := os.Executable()
	require.NoError(t, err)

	elfFile, err := elf.Open(executable)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, elfFile.Close())
	})
	return elfFile
}

func assertNoGoChannelLinkProbes(t *testing.T, probes map[string][]*ebpfcommon.ProbeDesc) {
	t.Helper()

	for _, symbol := range GoChannelLinkProbeSymbols() {
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
