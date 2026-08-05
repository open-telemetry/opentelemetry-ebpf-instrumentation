// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

const (
	h2FrameHeaderLen             = 9
	h2HeadersFrame               = 1
	h2SettingsFrame              = 4
	h2EndHeaders                 = 4
	h2HPACKTraceparentScanLimit  = 247
	h2KernelTailCallLimit        = 33
	nearMaxTraceparentValueBytes = 231
	outboundTraceWritten         = 1
	h2ClaimExistingTailSlot      = 13
	h2FirstScanContinuationSlot  = 15
	h2TestTrampolineTailSlot     = 0
	h2DetectTailSlot             = 8
)

var h2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

type h2PacketExtenderObjects struct {
	ObiPacketExtender                     *ebpf.Program `ebpf:"obi_packet_extender"`
	ObiPacketExtenderClaimExistingH2Tp    *ebpf.Program `ebpf:"obi_packet_extender_claim_existing_h2_tp"`
	ObiPacketExtenderContinueExistingH2Tp *ebpf.Program `ebpf:"obi_packet_extender_continue_existing_h2_tp"`
	ObiPacketExtenderDetectH2             *ebpf.Program `ebpf:"obi_packet_extender_detect_h2"`
	CpSupportConnectInfo                  *ebpf.Map     `ebpf:"cp_support_connect_info"`
	ExtenderJumpTable                     *ebpf.Map     `ebpf:"extender_jump_table"`
	OutgoingTraceHandoff                  *ebpf.Map     `ebpf:"outgoing_trace_handoff"`
	OutgoingTraceHandoffClaims            *ebpf.Map     `ebpf:"outgoing_trace_handoff_claims"`
	OutgoingTraceHandoffCPUClaims         *ebpf.Map     `ebpf:"outgoing_trace_handoff_cpu_claims"`
	OutgoingTraceHandoffEgressClaims      *ebpf.Map     `ebpf:"outgoing_trace_handoff_egress_claims"`
	OutgoingTraceHandoffLocators          *ebpf.Map     `ebpf:"outgoing_trace_handoff_locators"`
	OutgoingTraceHandoffSequence          *ebpf.Map     `ebpf:"outgoing_trace_handoff_sequence"`
	ServerTraces                          *ebpf.Map     `ebpf:"server_traces"`
	SockDir                               *ebpf.Map     `ebpf:"sock_dir"`
	TailcallCtxStorage                    *ebpf.Map     `ebpf:"tailcall_ctx_storage"`

	h2HpackOffsetField    int16
	h2HpackScanCallsField int16
	rewriteH2TPField      int16
}

func (o *h2PacketExtenderObjects) Close() error {
	return errors.Join(
		o.ObiPacketExtender.Close(),
		o.ObiPacketExtenderClaimExistingH2Tp.Close(),
		o.ObiPacketExtenderContinueExistingH2Tp.Close(),
		o.ObiPacketExtenderDetectH2.Close(),
		o.CpSupportConnectInfo.Close(),
		o.ExtenderJumpTable.Close(),
		o.OutgoingTraceHandoff.Close(),
		o.OutgoingTraceHandoffClaims.Close(),
		o.OutgoingTraceHandoffCPUClaims.Close(),
		o.OutgoingTraceHandoffEgressClaims.Close(),
		o.OutgoingTraceHandoffLocators.Close(),
		o.OutgoingTraceHandoffSequence.Close(),
		o.ServerTraces.Close(),
		o.SockDir.Close(),
		o.TailcallCtxStorage.Close(),
	)
}

type h2TraceparentFrame struct {
	streamID uint32
	traceID  string
	spanID   string
}

type h2TailcallCtxLayout struct {
	pConn              BpfPidConnectionInfoT
	parentTP           [48]byte
	eKey               BpfEgressKeyT
	h2FrameOffset      uint32
	h2PayloadLen       uint32
	h2HpackOffset      uint32
	h2HpackLen         uint32
	h2ScanPos          uint32
	h2TPCandidatePos   uint32
	h2TPValueLen       uint32
	http1SpanIDOffset  uint32
	http1ScanPos       uint32
	http1ValueOffset   uint32
	niter              uint8
	http1TPStatus      uint8
	h2Frames           uint8
	h2TPStatus         uint8
	h2TPValueHuffman   uint8
	h2TPRepresentation uint8
	hasParentTP        bool
	goH2Conn           bool
	tpPresent          bool
	scanExhausted      bool
	opener             uint8
	rewriteHTTP1TP     bool
	tcpOptionScheduled bool
	h2WireTraceID      [16]byte
	h2WireSpanID       [8]byte
	h2WireFlags        uint8
	rewriteH2TP        bool
	h2HandoffFresh     uint8
	h2HpackScanCalls   uint8
	h2HpackScanGuard   uint8
	h2TailCalls        uint8
	h2WirePad          [2]byte
	originalSpanID     [8]byte
	originalFlags      uint8
	handoffExpected    uint8
	tailPad            [5]byte
	handoffToken       BpfOutgoingTraceTokenT
}

const (
	h2HpackScanCallsOffset = unsafe.Offsetof(h2TailcallCtxLayout{}.h2HpackScanCalls)
	h2TailcallCtxSize      = unsafe.Sizeof(h2TailcallCtxLayout{})
)

type h2ScanRuntimeLayout struct {
	Prefix           [h2HpackScanCallsOffset]byte
	H2HpackScanCalls uint8
	H2HpackScanGuard uint8
	H2TailCalls      uint8
	Suffix           [h2TailcallCtxSize - h2HpackScanCallsOffset - 3]byte
}

func TestPacketExtenderH2MaxTailCallChain(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	objects := loadH2PacketExtender(t)
	attachPacketExtender(t, objects)

	client, server := tcpPair(t)
	preamble := h2Preamble()
	receivedPreamble := sendTCPChunk(t, client, server, preamble)

	// Backfilling the socket after its preface reserves the two-call sniff/detect prefix.
	// Raw future-version values fast-forward in one scan and validation pass, so all four
	// coalesced frames remain within the tail-call budget.
	trackTCPConn(t, objects.SockDir, client)

	headers, frames := maximalH2TraceparentBatch(t)
	require.Len(t, headers, len(frames)*(h2FrameHeaderLen+h2HPACKTraceparentScanLimit))
	receivedHeaders := sendFinalTCPChunk(t, client, server, headers)
	payload := append(append([]byte(nil), preamble...), headers...)
	received := append(receivedPreamble, receivedHeaders...)
	require.Equal(t, payload, received, "existing future-version traceparents must remain byte-for-byte unchanged")

	authorities := readH2Authorities(t, objects.OutgoingTraceHandoff)
	require.Len(t, authorities, len(frames))
	for _, frame := range frames {
		authority, ok := authorities[frame.streamID]
		require.Truef(t, ok, "missing authority for stream %d", frame.streamID)
		require.Equal(t, uint32(os.Getpid()), authority.Pid)
		require.Equal(t, uint8(1), authority.Valid)
		require.Equal(t, uint8(outboundTraceWritten), authority.Written)
		require.Equal(t, frame.traceID, hex.EncodeToString(authority.Tp.TraceId[:]))
		require.Equal(t, frame.spanID, hex.EncodeToString(authority.Tp.SpanId[:]))
		require.Equal(t, uint8(1), authority.Tp.Flags, "future-version flags must retain only sampled")
	}
	require.Equal(t,
		uint8(25),
		requireH2ScanTokensCleared(t, objects.TailcallCtxStorage),
		"four single-pass frames must retain their modeled tail-call cost")
}

func TestPacketExtenderH2DenseTailCallBudget(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	objects := loadH2PacketExtender(t)
	attachPacketExtender(t, objects)

	client, server := tcpPair(t)
	preamble := h2Preamble()
	receivedPreamble := sendTCPChunk(t, client, server, preamble)
	trackTCPConn(t, objects.SockDir, client)

	headers, frames := denseH2TraceparentBatch(t)
	receivedHeaders := sendFinalTCPChunk(t, client, server, headers)
	payload := append(append([]byte(nil), preamble...), headers...)
	received := append(receivedPreamble, receivedHeaders...)
	require.Equal(t, payload, received, "existing future-version traceparents must remain unchanged")

	authorities := readH2Authorities(t, objects.OutgoingTraceHandoff)
	require.Len(t, authorities, 1,
		"later dense frames must fail closed before exhausting the kernel tail-call chain")
	for _, frame := range frames[:1] {
		_, ok := authorities[frame.streamID]
		require.Truef(t, ok, "missing authority for stream %d", frame.streamID)
	}
	for _, frame := range frames[1:] {
		_, ok := authorities[frame.streamID]
		require.Falsef(t, ok, "over-budget stream %d cannot publish authority", frame.streamID)
	}
	require.Equal(t,
		uint8(h2KernelTailCallLimit),
		requireH2ScanTokensCleared(t, objects.TailcallCtxStorage),
		"the dense batch must exercise the runtime tail-call cap")
}

func TestPacketExtenderH2DynamicNameAcrossScanContinuation(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	objects := loadH2PacketExtender(t)
	attachPacketExtender(t, objects)

	client, server := tcpPair(t)
	preamble := h2Preamble()
	receivedPreamble := sendTCPChunk(t, client, server, preamble)
	trackTCPConn(t, objects.SockDir, client)

	frame, expected := sameBlockDynamicNameH2TraceparentFrame(t)
	receivedFrame := sendFinalTCPChunk(t, client, server, frame)
	require.Equal(t,
		append(append([]byte(nil), preamble...), frame...),
		append(receivedPreamble, receivedFrame...),
		"future-version application traceparent must remain unchanged")

	authorities := readH2Authorities(t, objects.OutgoingTraceHandoff)
	authority, ok := authorities[expected.streamID]
	require.True(t, ok, "current-block dynamic name must survive the scan continuation")
	require.Equal(t, expected.traceID, hex.EncodeToString(authority.Tp.TraceId[:]))
	require.Equal(t, expected.spanID, hex.EncodeToString(authority.Tp.SpanId[:]))
	requireH2ScanTokensCleared(t, objects.TailcallCtxStorage)
}

func TestPacketExtenderH2StaleScanTokenFailsClosed(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	objects := loadH2PacketExtender(t)
	attachPacketExtender(t, objects)
	installH2ScanTokenCorruptionShim(t, objects)

	client, server := tcpPair(t)
	preamble := h2Preamble()
	receivedPreamble := sendTCPChunk(t, client, server, preamble)
	trackTCPConn(t, objects.SockDir, client)

	frame := continuationH2TraceparentFrame(t)
	receivedFrame := sendFinalTCPChunk(t, client, server, frame)
	require.Equal(t,
		append(append([]byte(nil), preamble...), frame...),
		append(receivedPreamble, receivedFrame...),
		"a mismatched continuation token must leave the frame unchanged")
	require.Empty(t, readH2Authorities(t, objects.OutgoingTraceHandoff),
		"a stale continuation cannot publish traceparent authority")
	requireH2ScanTokensCleared(t, objects.TailcallCtxStorage)
}

func TestPacketExtenderH2ScanTailCallMissClearsToken(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	objects := loadH2PacketExtender(t)
	attachPacketExtender(t, objects)
	removeTailCallProgram(
		t, objects.ExtenderJumpTable, objects.ObiPacketExtenderContinueExistingH2Tp)

	client, server := tcpPair(t)
	preamble := h2Preamble()
	receivedPreamble := sendTCPChunk(t, client, server, preamble)
	trackTCPConn(t, objects.SockDir, client)

	frame := continuationH2TraceparentFrame(t)
	receivedFrame := sendFinalTCPChunk(t, client, server, frame)
	require.Equal(t,
		append(append([]byte(nil), preamble...), frame...),
		append(receivedPreamble, receivedFrame...),
		"a missing scan continuation must leave the frame unchanged")
	require.Empty(t, readH2Authorities(t, objects.OutgoingTraceHandoff),
		"a missing scan continuation cannot publish traceparent authority")
	requireH2ScanTokensCleared(t, objects.TailcallCtxStorage)
}

func TestPacketExtenderH2TailCallFailureCleansAndResumes(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	objects := loadH2PacketExtender(t)
	attachPacketExtender(t, objects)
	removeTailCallProgram(t, objects.ExtenderJumpTable, objects.ObiPacketExtenderClaimExistingH2Tp)

	client, server := tcpPair(t)
	preamble := h2Preamble()
	receivedPreamble := sendTCPChunk(t, client, server, preamble)
	trackTCPConn(t, objects.SockDir, client)

	headers, frames := shortFutureH2TraceparentBatch(t)
	detectCounter := installH2DetectCounter(t, objects)
	receivedHeaders := sendFinalTCPChunk(t, client, server, headers)
	var detectRuns uint64
	require.NoError(t, detectCounter.Lookup(uint32(0), &detectRuns))
	require.Equal(t, uint64(len(frames)), detectRuns,
		"detect must run once initially and once after each of the first three frames")
	payload := append(append([]byte(nil), preamble...), headers...)
	received := append(receivedPreamble, receivedHeaders...)
	require.Equal(t, payload, received, "a failed claim tail call must not mutate traceparent bytes")

	require.Empty(t, readH2Authorities(t, objects.OutgoingTraceHandoff),
		"fresh authorities must be retired when the claim tail call fails")
	require.Zero(t, countH2Locators(t, objects.OutgoingTraceHandoffLocators),
		"fresh authority locators must be retired when the claim tail call fails")
	require.Equal(t, uint64(len(frames)), sumPerCPUSequence(t, objects.OutgoingTraceHandoffSequence),
		"every frame must resume far enough to attempt its own reservation")
}

func installH2DetectCounter(t *testing.T, objects *h2PacketExtenderObjects) *ebpf.Map {
	t.Helper()

	counter, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "h2_detect_runs",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, counter.Close()) })

	originalSlot := uint32(h2TestTrampolineTailSlot)
	require.NoError(t, objects.ExtenderJumpTable.Update(
		&originalSlot, uint32(objects.ObiPacketExtenderDetectH2.FD()), ebpf.UpdateAny))

	wrapper, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:       "count_h2_detect",
		Type:       ebpf.SkMsg,
		AttachType: ebpf.AttachSkMsgVerdict,
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, counter.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "detect"),
			asm.Mov.Imm(asm.R7, 1),
			asm.StoreXAdd(asm.R0, asm.R7, asm.DWord),
			asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("detect"),
			asm.LoadMapPtr(asm.R2, objects.ExtenderJumpTable.FD()),
			asm.Mov.Imm(asm.R3, h2TestTrampolineTailSlot),
			asm.FnTailCall.Call(),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
		License: "GPL",
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, wrapper.Close()) })

	detectSlot := uint32(h2DetectTailSlot)
	require.NoError(t, objects.ExtenderJumpTable.Update(&detectSlot, uint32(wrapper.FD()), ebpf.UpdateAny))
	return counter
}

func installH2ScanTokenCorruptionShim(t *testing.T, objects *h2PacketExtenderObjects) {
	t.Helper()

	originalSlot := uint32(h2TestTrampolineTailSlot)
	require.NoError(t, objects.ExtenderJumpTable.Update(
		&originalSlot, uint32(objects.ObiPacketExtenderContinueExistingH2Tp.FD()), ebpf.UpdateAny))

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, objects.TailcallCtxStorage.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "resume"),
		asm.StoreImm(asm.R0, objects.h2HpackScanCallsField, 1, asm.Byte),
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("resume"),
		asm.LoadMapPtr(asm.R2, objects.ExtenderJumpTable.FD()),
		asm.Mov.Imm(asm.R3, h2TestTrampolineTailSlot),
		asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),
	}
	shim, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "h2_bad_scan_tok",
		Type:         ebpf.SkMsg,
		AttachType:   ebpf.AttachSkMsgVerdict,
		Instructions: instructions,
		License:      "GPL",
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, shim.Close()) })

	continuationSlot := uint32(h2FirstScanContinuationSlot)
	require.NoError(
		t, objects.ExtenderJumpTable.Update(&continuationSlot, uint32(shim.FD()), ebpf.UpdateAny))
}

func TestPacketExtenderH2RewriteWriteFailureRetries(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	objects := loadH2PacketExtender(t)
	attachPacketExtender(t, objects)
	installH2RewriteWriteFailureShim(t, objects)

	client, server := tcpPair(t)
	preamble := h2Preamble()
	require.Equal(t, preamble, sendTCPChunk(t, client, server, preamble))
	trackTCPConn(t, objects.SockDir, client)

	const traceID = "00112233445566778899aabbccddeeff"
	const forwardedSpanID = "0123456789abcdef"
	const parentSpanID = "fedcba9876543210"
	installH2ProxyParent(t, objects, client, traceID, forwardedSpanID, parentSpanID)

	headers, frames := rewriteEligibleH2TraceparentFrames(t, traceID, forwardedSpanID)
	var received []byte
	for _, header := range headers {
		received = append(received, sendTCPChunk(t, client, server, header)...)
	}
	require.Equal(t, bytes.Join(headers, nil), received,
		"failed rewrites must leave all application traceparents byte-for-byte unchanged")

	authorities := readH2Authorities(t, objects.OutgoingTraceHandoff)
	require.Len(t, authorities, len(frames), "each retry must commit one fallback authority")
	for _, frame := range frames {
		authority, ok := authorities[frame.streamID]
		require.Truef(t, ok, "missing fallback authority for stream %d", frame.streamID)
		require.Equal(t, traceID, hex.EncodeToString(authority.Tp.TraceId[:]))
		require.Equal(t, forwardedSpanID, hex.EncodeToString(authority.Tp.SpanId[:]))
		require.Equal(t, "0000000000000000", hex.EncodeToString(authority.Tp.ParentId[:]),
			"fallback authority must restore the application traceparent's remote-parent semantics")
		require.Equal(t, uint8(outboundTraceWritten), authority.Written)
	}
	require.Equal(t, len(frames), countH2Locators(t, objects.OutgoingTraceHandoffLocators),
		"retired failed reservations must not leak locators")
	require.Zero(t, countMapEntries(t, objects.OutgoingTraceHandoffClaims),
		"retry must release exact-generation claims")
	require.Zero(t, countMapEntries(t, objects.OutgoingTraceHandoffCPUClaims),
		"retry must release sequence claims")
	require.Zero(t, countMapEntries(t, objects.OutgoingTraceHandoffEgressClaims),
		"retry must release reservation claims")
	require.Equal(t, uint64(2*len(frames)), sumPerCPUSequence(t, objects.OutgoingTraceHandoffSequence),
		"each frame must retire its failed reservation and reserve one fallback authority")
}

func loadH2PacketExtender(t *testing.T) *h2PacketExtenderObjects {
	t.Helper()

	spec, err := LoadBpf()
	require.NoError(t, err)
	ctxLayout := h2TailcallCtxLayout{}
	h2HpackOffsetField := int16(unsafe.Offsetof(ctxLayout.h2HpackOffset))
	h2HpackScanCallsField := int16(unsafe.Offsetof(ctxLayout.h2HpackScanCalls))
	rewriteH2TPField := int16(unsafe.Offsetof(ctxLayout.rewriteH2TP))
	require.Equal(t, uint32(unsafe.Sizeof(ctxLayout)), spec.Maps[BpfMapTailcallCtxStorage].ValueSize)
	ebpfconvenience.SetupMapSizes(spec, -6)

	sharedMaps := map[string]*ebpf.Map{}
	var sharedMapsMu sync.Mutex
	objects := &h2PacketExtenderObjects{}
	require.NoError(t, ebpfconvenience.LoadSpec(spec, objects, map[string]any{
		"filter_pids":          int32(0),
		"max_transaction_time": uint64(time.Minute),
		"inject_flags":         uint32(1),
		"g_bpf_debug":          false,
	}, sharedMaps, &sharedMapsMu, "", nil))
	objects.h2HpackOffsetField = h2HpackOffsetField
	objects.h2HpackScanCallsField = h2HpackScanCallsField
	objects.rewriteH2TPField = rewriteH2TPField

	t.Cleanup(func() {
		require.NoError(t, objects.Close())
		for name, bpfMap := range sharedMaps {
			require.NoErrorf(t, bpfMap.Close(), "close shared BPF map %s", name)
		}
	})
	return objects
}

func installH2RewriteWriteFailureShim(t *testing.T, objects *h2PacketExtenderObjects) {
	t.Helper()

	originalSlot := uint32(h2TestTrampolineTailSlot)
	require.NoError(t, objects.ExtenderJumpTable.Update(
		&originalSlot, uint32(objects.ObiPacketExtenderClaimExistingH2Tp.FD()), ebpf.UpdateAny))

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, objects.TailcallCtxStorage.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "claim"),
		asm.LoadMem(asm.R7, asm.R0, objects.rewriteH2TPField, asm.Byte),
		asm.JEq.Imm(asm.R7, 0, "claim"),
		asm.StoreImm(asm.R0, objects.h2HpackOffsetField, 1<<30, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("claim"),
		asm.LoadMapPtr(asm.R2, objects.ExtenderJumpTable.FD()),
		asm.Mov.Imm(asm.R3, h2TestTrampolineTailSlot),
		asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),
	}
	shim, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "h2_write_failure",
		Type:         ebpf.SkMsg,
		AttachType:   ebpf.AttachSkMsgVerdict,
		Instructions: instructions,
		License:      "GPL",
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, shim.Close()) })

	claimSlot := uint32(h2ClaimExistingTailSlot)
	require.NoError(t, objects.ExtenderJumpTable.Update(&claimSlot, uint32(shim.FD()), ebpf.UpdateAny))
}

func installH2ProxyParent(
	t *testing.T,
	objects *h2PacketExtenderObjects,
	client *net.TCPConn,
	traceID string,
	forwardedSpanID string,
	parentSpanID string,
) {
	t.Helper()

	traceKey := BpfTraceKeyT{ExtraId: 1}
	traceKey.P_key.Tid = uint32(os.Getpid())
	traceKey.P_key.Pid = uint32(os.Getpid())

	var now unix.Timespec
	require.NoError(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &now))
	parent := BpfTpInfoPidT{
		Pid:   uint32(os.Getpid()),
		Valid: 1,
	}
	copy(parent.Tp.TraceId[:], mustDecodeHex(t, traceID))
	copy(parent.Tp.SpanId[:], mustDecodeHex(t, parentSpanID))
	copy(parent.Tp.ParentId[:], mustDecodeHex(t, forwardedSpanID))
	parent.Tp.Ts = uint64(now.Nano())
	parent.Tp.Flags = 1
	require.NoError(t, objects.ServerTraces.Update(&traceKey, &parent, ebpf.UpdateAny))

	pConn := h2ClientConnectionKey(t, client)
	connectionParent := BpfCpSupportDataT{T_key: traceKey}
	require.NoError(t, objects.CpSupportConnectInfo.Update(&pConn, &connectionParent, ebpf.UpdateAny))
}

func h2ClientConnectionKey(t *testing.T, client *net.TCPConn) BpfPidConnectionInfoT {
	t.Helper()

	local := client.LocalAddr().(*net.TCPAddr)
	remote := client.RemoteAddr().(*net.TCPAddr)
	key := BpfPidConnectionInfoT{Pid: uint32(os.Getpid())}
	key.Conn.S_addr = h2MappedIPv4(t, local.IP)
	key.Conn.D_addr = h2MappedIPv4(t, remote.IP)
	key.Conn.S_port = uint16(local.Port)
	key.Conn.D_port = uint16(remote.Port)

	sourceEphemeral := key.Conn.S_port >= 32768
	destinationEphemeral := key.Conn.D_port >= 32768
	if !(sourceEphemeral && !destinationEphemeral) &&
		((destinationEphemeral && !sourceEphemeral) || key.Conn.D_port > key.Conn.S_port) {
		key.Conn.S_addr, key.Conn.D_addr = key.Conn.D_addr, key.Conn.S_addr
		key.Conn.S_port, key.Conn.D_port = key.Conn.D_port, key.Conn.S_port
	}
	return key
}

func h2MappedIPv4(t *testing.T, ip net.IP) [16]uint8 {
	t.Helper()

	v4 := ip.To4()
	require.NotNil(t, v4)
	var mapped [16]uint8
	mapped[10] = 0xff
	mapped[11] = 0xff
	copy(mapped[12:], v4)
	return mapped
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return decoded
}

func attachPacketExtender(t *testing.T, objects *h2PacketExtenderObjects) {
	t.Helper()

	opts := link.RawAttachProgramOptions{
		Target:  objects.SockDir.FD(),
		Program: objects.ObiPacketExtender,
		Attach:  ebpf.AttachSkMsgVerdict,
	}
	require.NoError(t, link.RawAttachProgram(opts))
	t.Cleanup(func() {
		require.NoError(t, link.RawDetachProgram(link.RawDetachProgramOptions(opts)))
	})
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	server, err := listener.AcceptTCP()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })

	return client, server
}

func trackTCPConn(t *testing.T, sockDir *ebpf.Map, client *net.TCPConn) {
	t.Helper()

	raw, err := client.SyscallConn()
	require.NoError(t, err)
	var updateErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		cookie, err := unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			updateErr = fmt.Errorf("get client socket cookie: %w", err)
			return
		}
		updateErr = sockDir.Update(&cookie, uint32(fd), ebpf.UpdateAny)
	}))
	require.NoError(t, updateErr)
}

func sendTCPChunk(t *testing.T, client, server *net.TCPConn, payload []byte) []byte {
	t.Helper()

	require.NoError(t, client.SetWriteDeadline(time.Now().Add(5*time.Second)))
	written, err := client.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), written)

	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	received := make([]byte, len(payload))
	_, err = io.ReadFull(server, received)
	require.NoError(t, err)
	return received
}

func sendFinalTCPChunk(t *testing.T, client, server *net.TCPConn, payload []byte) []byte {
	t.Helper()

	require.NoError(t, client.SetWriteDeadline(time.Now().Add(5*time.Second)))
	written, err := client.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), written)
	require.NoError(t, client.CloseWrite())

	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	received, err := io.ReadAll(server)
	require.NoError(t, err)
	return received
}

func maximalH2TraceparentBatch(t *testing.T) ([]byte, []h2TraceparentFrame) {
	t.Helper()

	var payload []byte
	frames := make([]h2TraceparentFrame, 0, 4)
	for i, streamID := range []uint32{1, 3, 5, 7} {
		traceID := fmt.Sprintf("%032x", streamID)
		spanID := fmt.Sprintf("%016x", streamID+100)
		value := []byte("01-" + traceID + "-" + spanID + "-85-" +
			strings.Repeat(string(rune('a'+i)), nearMaxTraceparentValueBytes-56))
		require.Len(t, value, nearMaxTraceparentValueBytes)

		block := []byte{0x82, 0x10}
		block = appendHPACKString(block, []byte("traceparent"))
		block = appendHPACKString(block, value)
		require.Len(t, block, h2HPACKTraceparentScanLimit)

		wire := h2Frame(h2HeadersFrame, h2EndHeaders, streamID, block)
		payload = append(payload, wire...)
		frames = append(frames, h2TraceparentFrame{
			streamID: streamID,
			traceID:  traceID,
			spanID:   spanID,
		})
	}

	return payload, frames
}

func denseH2TraceparentBatch(t *testing.T) ([]byte, []h2TraceparentFrame) {
	t.Helper()

	var payload []byte
	frames := make([]h2TraceparentFrame, 0, 4)
	for i, streamID := range []uint32{1, 3, 5, 7} {
		traceID := fmt.Sprintf("%032x", streamID)
		spanID := fmt.Sprintf("%016x", streamID+100)
		value := []byte("01-" + traceID + "-" + spanID + "-85-" + string(rune('a'+i)))

		block := bytes.Repeat([]byte{0x82}, 150)
		block = append(block, 0x10)
		block = appendHPACKString(block, []byte("traceparent"))
		block = appendHPACKString(block, value)
		block = append(block, bytes.Repeat([]byte{0x82}, h2HPACKTraceparentScanLimit-len(block))...)
		require.Len(t, block, h2HPACKTraceparentScanLimit)

		payload = append(payload, h2Frame(h2HeadersFrame, h2EndHeaders, streamID, block)...)
		frames = append(frames, h2TraceparentFrame{
			streamID: streamID,
			traceID:  traceID,
			spanID:   spanID,
		})
	}

	return payload, frames
}

func sameBlockDynamicNameH2TraceparentFrame(t *testing.T) ([]byte, h2TraceparentFrame) {
	t.Helper()

	const (
		traceID = "00000000000000000000000000000001"
		spanID  = "0000000000000065"
	)
	block := []byte{0x82, 0x40, 0x01, 'x', 0x00}
	block = append(block, bytes.Repeat([]byte{0x82}, 11)...)
	// Literal without indexing, dynamic name index 62, empty value.
	block = append(block, 0x0f, 0x2f, 0x00)
	block = append(block, 0x10)
	block = appendHPACKString(block, []byte("traceparent"))
	block = appendHPACKString(block, []byte("01-"+traceID+"-"+spanID+"-85-a"))

	expected := h2TraceparentFrame{streamID: 1, traceID: traceID, spanID: spanID}
	return h2Frame(h2HeadersFrame, h2EndHeaders, expected.streamID, block), expected
}

func continuationH2TraceparentFrame(t *testing.T) []byte {
	t.Helper()

	const traceID = "00000000000000000000000000000001"
	const spanID = "0000000000000065"
	value := []byte("00-" + traceID + "-" + spanID + "-01")
	block := bytes.Repeat([]byte{0x82}, 100)
	block = append(block, 0x10)
	block = appendHPACKString(block, []byte("traceparent"))
	block = appendHPACKString(block, value)
	block = append(block, bytes.Repeat([]byte{0x82}, h2HPACKTraceparentScanLimit-len(block))...)
	require.Len(t, block, h2HPACKTraceparentScanLimit)
	return h2Frame(h2HeadersFrame, h2EndHeaders, 1, block)
}

func shortFutureH2TraceparentBatch(t *testing.T) ([]byte, []h2TraceparentFrame) {
	t.Helper()

	var payload []byte
	frames := make([]h2TraceparentFrame, 0, 4)
	for _, streamID := range []uint32{1, 3, 5, 7} {
		traceID := fmt.Sprintf("%032x", streamID)
		spanID := fmt.Sprintf("%016x", streamID+100)
		value := []byte("01-" + traceID + "-" + spanID + "-01")

		block := []byte{0x82, 0x10}
		block = appendHPACKString(block, []byte("traceparent"))
		block = appendHPACKString(block, value)
		payload = append(payload, h2Frame(h2HeadersFrame, h2EndHeaders, streamID, block)...)
		frames = append(frames, h2TraceparentFrame{
			streamID: streamID,
			traceID:  traceID,
			spanID:   spanID,
		})
	}
	return payload, frames
}

func rewriteEligibleH2TraceparentFrames(
	t *testing.T, traceID, spanID string,
) ([][]byte, []h2TraceparentFrame) {
	t.Helper()

	wires := make([][]byte, 0, 4)
	frames := make([]h2TraceparentFrame, 0, 4)
	for _, streamID := range []uint32{1, 3, 5, 7} {
		value := []byte("00-" + traceID + "-" + spanID + "-01")
		require.Len(t, value, 55)

		block := []byte{0x82, 0x10}
		block = appendHPACKString(block, []byte("traceparent"))
		block = appendHPACKString(block, value)
		wires = append(wires, h2Frame(h2HeadersFrame, h2EndHeaders, streamID, block))
		frames = append(frames, h2TraceparentFrame{
			streamID: streamID,
			traceID:  traceID,
			spanID:   spanID,
		})
	}
	return wires, frames
}

func h2Preamble() []byte {
	preamble := append([]byte(nil), h2ClientPreface...)
	return append(preamble, h2Frame(h2SettingsFrame, 0, 0, nil)...)
}

func appendHPACKString(dst, value []byte) []byte {
	length := len(value)
	if length < 0x7f {
		dst = append(dst, byte(length))
	} else {
		dst = append(dst, 0x7f)
		length -= 0x7f
		for length >= 0x80 {
			dst = append(dst, byte(length)|0x80)
			length >>= 7
		}
		dst = append(dst, byte(length))
	}
	return append(dst, value...)
}

func h2Frame(frameType, flags uint8, streamID uint32, payload []byte) []byte {
	wire := make([]byte, h2FrameHeaderLen, h2FrameHeaderLen+len(payload))
	wire[0] = byte(len(payload) >> 16)
	wire[1] = byte(len(payload) >> 8)
	wire[2] = byte(len(payload))
	wire[3] = frameType
	wire[4] = flags
	wire[5] = byte(streamID >> 24)
	wire[6] = byte(streamID >> 16)
	wire[7] = byte(streamID >> 8)
	wire[8] = byte(streamID)
	return append(wire, payload...)
}

func readH2Authorities(t *testing.T, handoffs *ebpf.Map) map[uint32]BpfTpInfoPidT {
	t.Helper()

	authorities := map[uint32]BpfTpInfoPidT{}
	iterator := handoffs.Iterate()
	var key BpfOutgoingTraceHandoffKeyT
	var value BpfOutgoingTraceHandoffT
	for iterator.Next(&key, &value) {
		require.NotZero(t, key.Token.MapEpoch)
		require.NotZero(t, key.Token.Sequence)
		require.NotZero(t, key.Token.ProcessStartTime)
		require.Falsef(t, bytes.Equal(value.Tp.Tp.TraceId[:], make([]byte, 16)),
			"zero trace ID for stream %d", key.Egress.StreamId)
		_, exists := authorities[key.Egress.StreamId]
		require.Falsef(t, exists, "duplicate authority for stream %d", key.Egress.StreamId)
		authorities[key.Egress.StreamId] = value.Tp
	}
	require.NoError(t, iterator.Err())
	return authorities
}

func removeTailCallProgram(t *testing.T, jumpTable *ebpf.Map, program *ebpf.Program) {
	t.Helper()

	programInfo, err := program.Info()
	require.NoError(t, err)
	programID, ok := programInfo.ID()
	require.True(t, ok)

	mapInfo, err := jumpTable.Info()
	require.NoError(t, err)
	for slot := uint32(0); slot < mapInfo.MaxEntries; slot++ {
		var currentID uint32
		err := jumpTable.Lookup(&slot, &currentID)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		require.NoError(t, err)
		if ebpf.ProgramID(currentID) == programID {
			require.NoError(t, jumpTable.Delete(&slot))
			return
		}
	}
	t.Fatalf("program %d is absent from the extender jump table", programID)
}

func countH2Locators(t *testing.T, locators *ebpf.Map) int {
	t.Helper()

	count := 0
	iterator := locators.Iterate()
	var key BpfEgressKeyT
	var value BpfOutgoingTraceTokenT
	for iterator.Next(&key, &value) {
		count++
	}
	require.NoError(t, iterator.Err())
	return count
}

func countMapEntries(t *testing.T, bpfMap *ebpf.Map) int {
	t.Helper()

	info, err := bpfMap.Info()
	require.NoError(t, err)
	key := make([]byte, info.KeySize)
	value := make([]byte, info.ValueSize)
	count := 0
	iterator := bpfMap.Iterate()
	for iterator.Next(&key, &value) {
		count++
	}
	require.NoError(t, iterator.Err())
	return count
}

func sumPerCPUSequence(t *testing.T, sequenceMap *ebpf.Map) uint64 {
	t.Helper()

	possibleCPUs, err := ebpf.PossibleCPU()
	require.NoError(t, err)
	values := make([]uint64, possibleCPUs)
	require.NoError(t, sequenceMap.Lookup(uint32(0), values))
	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}

func requireH2ScanTokensCleared(t *testing.T, tailcallCtxStorage *ebpf.Map) uint8 {
	t.Helper()

	possibleCPUs, err := ebpf.PossibleCPU()
	require.NoError(t, err)
	contexts := make([]h2ScanRuntimeLayout, possibleCPUs)
	require.NoError(t, tailcallCtxStorage.Lookup(uint32(0), contexts))
	var maxTailCalls uint8
	for cpu, context := range contexts {
		require.Zerof(t, context.H2HpackScanCalls, "stale H2 scan token on CPU %d", cpu)
		require.Zerof(t, context.H2HpackScanGuard, "stale H2 scan guard on CPU %d", cpu)
		require.LessOrEqualf(t,
			context.H2TailCalls,
			uint8(h2KernelTailCallLimit),
			"H2 tail-call budget exceeded on CPU %d",
			cpu)
		if context.H2TailCalls > maxTailCalls {
			maxTailCalls = context.H2TailCalls
		}
	}
	return maxTailCalls
}
