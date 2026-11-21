// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	"errors"
	"runtime"
	"slices"
	"strings"

	"github.com/ianlancetaylor/demangle"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type rustProbeKind uint8

const (
	rustTaskNew rustProbeKind = iota
	rustTaskRawNew
	rustTaskBind
	rustTaskPoll
	rustTaskDealloc
	rustTaskSpawn
	rustTaskSpawnPublic
	rustTaskSchedule
	rustTaskScheduleLocal
	rustTaskPublish
	rustTaskHarnessPoll
	rustTaskHarnessDealloc
	rustHyperEnqueue
	rustHyperDequeue
	rustHyperSend
	rustHyperChanSend
	rustHyperReceive
	rustHyperFindBlock
	rustHyperRequestSend
	rustHyperRequestReceive
	rustHyperClear
	rustHyperPop
	rustTLSClientProcess
	rustTLSServerProcess
	rustTLSClientLegacyProcess
	rustTLSServerLegacyProcess
	rustTLSChunk
	rustTLSConsume
	rustTLSWrite
	rustTLSWriteVectored
	rustTLSRead
	rustTLSReaderRead
	rustHTTP1Headers
	rustHTTP1HeadersOriginal
	rustH2SendHeaders
	rustH2BufferPending
	rustH2PollComplete
	rustH2PrioritizePending
	rustH2PrioritizeComplete
	rustH2Encode
	rustH2TakeRequest
	rustH2TakeStreamRequest
	rustH2HPACK
	rustTLSFlush
	rustTLSFlushBuffer
	rustProbeCount
)

type rustProbeSymbols struct {
	addresses     [rustProbeCount][]uint64
	channels      []string
	channelProbes map[string]map[rustProbeKind][]uint64
	hasHyper      bool
	hasTokio      bool
}

func resolveRustProbes(f *elf.File) (rustProbeSymbols, error) {
	probes := rustProbeSymbols{channelProbes: map[string]map[rustProbeKind][]uint64{}}

	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB ||
		(f.Machine != elf.EM_X86_64 || runtime.GOARCH != "amd64") &&
			(f.Machine != elf.EM_AARCH64 || runtime.GOARCH != "arm64") {
		return probes, errors.New("rust uprobes require a native 64-bit amd64 or arm64 executable")
	}

	hasHyper := false
	hasTokio := false
	channelTypes := map[string]struct{}{}
	// Demangling dominates the scan, so each match keeps what its name decoded to.
	type rustSymbolMatch struct {
		kind     rustProbeKind
		envelope string
	}
	matches := map[string]rustSymbolMatch{}

	syms, err := procs.FindExeSymbolsMatching(f, func(name string) bool {
		if !strings.HasPrefix(name, "_R") && !strings.HasPrefix(name, "_ZN") {
			return false
		}

		if !strings.Contains(name, "tokio") && !strings.Contains(name, "hyper") && !strings.Contains(name, "rustls") && !strings.Contains(name, "h2") {
			return false
		}

		decoded, err := demangle.ToString(name, demangle.NoClones, demangle.MaxLength(16))
		if err != nil {
			return false
		}

		if strings.Contains(decoded, "hyper::client::") {
			hasHyper = true
		}

		if strings.Contains(decoded, "tokio::runtime::") {
			hasTokio = true
		}

		kind, ok := rustSymbolKind(decoded)
		if !ok {
			return false
		}

		match := rustSymbolMatch{kind: kind}
		if kind >= rustHyperEnqueue && kind <= rustHyperPop {
			match.envelope = rustHyperEnvelope(decoded)
			if match.envelope != "" {
				channelTypes[match.envelope] = struct{}{}
			}
		}

		// The callback's names alias an ELF mapping that closes after the scan.
		matches[strings.Clone(name)] = match
		return true
	})
	if err != nil {
		return probes, err
	}

	for name := range channelTypes {
		probes.channels = append(probes.channels, name)
	}

	probes.hasHyper = hasHyper
	probes.hasTokio = hasTokio

	for name, sym := range syms {
		match := matches[name]
		kind := match.kind
		if kind >= rustHyperEnqueue && kind <= rustHyperPop {
			envelope := match.envelope
			if probes.channelProbes[envelope] == nil {
				probes.channelProbes[envelope] = map[rustProbeKind][]uint64{}
			}

			probes.channelProbes[envelope][kind] = append(probes.channelProbes[envelope][kind], sym.Off)
		}

		probes.addresses[kind] = append(probes.addresses[kind], sym.Off)
	}

	for kind := range probes.addresses {
		slices.Sort(probes.addresses[kind])
		probes.addresses[kind] = slices.Compact(probes.addresses[kind])
	}

	if len(syms) == 0 {
		return rustProbeSymbols{}, errors.New("no supported Rust runtime or protocol symbols found")
	}

	slices.Sort(probes.channels)
	return probes, nil
}

func rustHyperEnvelope(name string) string {
	prefix := "hyper::client::dispatch::Envelope<"
	start := strings.Index(name, prefix)

	if start < 0 {
		for _, candidate := range []string{"hyper::client::dispatch::Sender<", "hyper::client::dispatch::UnboundedSender<"} {
			if position := strings.Index(name, candidate); position >= 0 {
				prefix, start = candidate, position
				break
			}
		}

		if start < 0 {
			return ""
		}
	}

	depth := 1
	for i := start + len(prefix); i < len(name); i++ {
		switch name[i] {
		case '<':
			depth++
		case '>':
			depth--
			if depth == 0 {
				return "hyper::client::dispatch::Envelope<" + name[start+len(prefix):i] + ">"
			}
		}
	}

	return ""
}

func rustSymbolKind(name string) (rustProbeKind, bool) {
	if name == "<rustls::vecbuf::ChunkVecBuffer>::write_to" {
		return rustTLSFlushBuffer, true
	}

	if name == "<rustls::conn::CommonState>::write_tls" ||
		strings.HasPrefix(name, "<rustls::conn::ConnectionCommon<") && strings.HasSuffix(name, ">::write_tls") {
		return rustTLSFlush, true
	}

	if (strings.HasPrefix(name, "<hyper::client::dispatch::Sender<http::request::Request<") ||
		strings.HasPrefix(name, "<hyper::client::dispatch::UnboundedSender<http::request::Request<")) &&
		(strings.HasSuffix(name, ">::send") || strings.HasSuffix(name, ">::try_send")) {
		return rustHyperRequestSend, true
	}

	if name == "<tokio::runtime::scheduler::multi_thread::handle::Handle>::schedule_option_task_without_yield" {
		return rustTaskPublish, true
	}

	if strings.HasPrefix(name, "tokio::task::spawn::spawn::<") && strings.HasSuffix(name, ">") {
		return rustTaskSpawnPublic, true
	}

	if strings.HasPrefix(name, "<tokio::runtime::task::raw::RawTask>::new::<") && strings.HasSuffix(name, ">") {
		return rustTaskRawNew, true
	}

	if strings.HasPrefix(name, "<tokio::runtime::task::harness::Harness<") {
		if strings.HasSuffix(name, ">::poll") {
			return rustTaskHarnessPoll, true
		}

		if strings.HasSuffix(name, ">::dealloc") {
			return rustTaskHarnessDealloc, true
		}
	}

	if (strings.HasPrefix(name, "<tokio::runtime::scheduler::Handle>::spawn::<") ||
		strings.HasPrefix(name, "<tokio::runtime::scheduler::multi_thread::handle::Handle>::spawn::<") ||
		strings.HasPrefix(name, "<tokio::runtime::scheduler::current_thread::Handle>::spawn::<") ||
		strings.HasPrefix(name, "<tokio::runtime::thread_pool::Spawner>::spawn::<") ||
		strings.HasPrefix(name, "<tokio::runtime::basic_scheduler::Spawner>::spawn::<")) && strings.HasSuffix(name, ">") {
		return rustTaskSpawn, true
	}

	if name == "<tokio::runtime::thread_pool::worker::Shared>::schedule" ||
		name == "<alloc::sync::Arc<tokio::runtime::scheduler::multi_thread::handle::Handle> as tokio::runtime::task::Schedule>::schedule" ||
		name == "<alloc::sync::Arc<tokio::runtime::scheduler::current_thread::Handle> as tokio::runtime::task::Schedule>::schedule" ||
		name == "<alloc::sync::Arc<tokio::runtime::basic_scheduler::Shared> as tokio::runtime::task::Schedule>::schedule" {
		return rustTaskSchedule, true
	}

	if name == "<tokio::runtime::scheduler::multi_thread::handle::Handle>::schedule_local" {
		return rustTaskScheduleLocal, true
	}

	if strings.HasPrefix(name, "<tokio::sync::mpsc::list::Tx<hyper::client::dispatch::Envelope<") && strings.HasSuffix(name, ">::find_block") {
		return rustHyperFindBlock, true
	}

	if strings.HasPrefix(name, "<tokio::sync::mpsc::list::Rx<hyper::client::dispatch::Envelope<") && strings.HasSuffix(name, ">::pop") {
		return rustHyperPop, true
	}

	if strings.HasPrefix(name, "<tokio::runtime::task::list::OwnedTasks<") && strings.HasSuffix(name, ">::bind_inner") {
		return rustTaskBind, true
	}

	if strings.HasPrefix(name, "<tokio::sync::mpsc::list::Tx<hyper::client::dispatch::Envelope<") && strings.HasSuffix(name, ">::push") {
		return rustHyperSend, true
	}

	if strings.HasPrefix(name, "<tokio::sync::mpsc::chan::Tx<hyper::client::dispatch::Envelope<") && strings.HasSuffix(name, ">::send") {
		return rustHyperChanSend, true
	}

	if strings.HasPrefix(name, "<tokio::sync::mpsc::chan::Rx<hyper::client::dispatch::Envelope<") && strings.HasSuffix(name, ">::recv") {
		return rustHyperReceive, true
	}

	if name == "<h2::hpack::encoder::Encoder>::encode::<h2::frame::headers::Iter>" {
		return rustH2HPACK, true
	}

	if strings.HasPrefix(name, "hyper::proto::h1::role::") {
		switch name {
		case "hyper::proto::h1::role::write_headers", "hyper::proto::h1::role::write_headers_title_case":
			return rustHTTP1Headers, true
		case "hyper::proto::h1::role::write_headers_original_case":
			return rustHTTP1HeadersOriginal, true
		}
	}

	if strings.HasPrefix(name, "<h2::proto::streams::prioritize::Prioritize>") && strings.HasSuffix(name, ">") {
		if strings.Contains(name, "::buffer_pending::<") {
			return rustH2PrioritizePending, true
		}

		if strings.Contains(name, "::poll_complete::<") {
			return rustH2PrioritizeComplete, true
		}
	}

	if strings.HasPrefix(name, "<h2::proto::streams::send::Send>") {
		if strings.Contains(name, "::send_headers::<") && strings.HasSuffix(name, ">") {
			return rustH2SendHeaders, true
		}

		if strings.Contains(name, "::buffer_pending::<") && strings.HasSuffix(name, ">") {
			return rustH2BufferPending, true
		}

		if strings.Contains(name, "::poll_complete::<") && strings.HasSuffix(name, ">") {
			return rustH2PollComplete, true
		}
	}

	if strings.HasPrefix(name, "<h2::proto::streams::streams::StreamRef<") && strings.HasSuffix(name, ">::take_request") {
		return rustH2TakeStreamRequest, true
	}

	if name == "<h2::proto::streams::recv::Recv>::take_request" {
		return rustH2TakeRequest, true
	}

	if strings.HasPrefix(name, "<h2::frame::headers::Headers>") {
		if strings.HasSuffix(name, "::encode") {
			return rustH2Encode, true
		}
	}

	if strings.HasSuffix(name, ">::process_new_packets") {
		client := strings.Contains(name, "rustls::client::client_conn::")
		server := strings.Contains(name, "rustls::server::server_conn::")
		if strings.HasPrefix(name, "<rustls::conn::ConnectionCore<") {
			if client {
				return rustTLSClientProcess, true
			}

			if server {
				return rustTLSServerProcess, true
			}
		}

		if strings.HasPrefix(name, "<rustls::conn::ConnectionCommon<") {
			if client {
				return rustTLSClientLegacyProcess, true
			}

			if server {
				return rustTLSServerLegacyProcess, true
			}
		}
	}

	if name == "<rustls::conn::connection::Reader>::into_first_chunk" {
		return rustTLSChunk, true
	}

	if name == "<rustls::vecbuf::ChunkVecBuffer>::consume_first_chunk" {
		return rustTLSConsume, true
	}

	if (strings.HasPrefix(name, "<rustls::conn::Reader as ") || strings.HasPrefix(name, "<rustls::conn::connection::Reader as ")) &&
		(strings.HasSuffix(name, "::read::Read>::read") || strings.HasSuffix(name, "::Read>::read")) {
		return rustTLSReaderRead, true
	}

	if name == "<rustls::vecbuf::ChunkVecBuffer>::read" {
		return rustTLSRead, true
	}

	if strings.HasPrefix(name, "<rustls::conn::ConnectionCommon<") {
		if strings.HasSuffix(name, " as rustls::conn::connection::PlaintextSink>::write") || strings.HasSuffix(name, " as rustls::conn::PlaintextSink>::write") {
			return rustTLSWrite, true
		}

		if strings.HasSuffix(name, " as rustls::conn::connection::PlaintextSink>::write_vectored") || strings.HasSuffix(name, " as rustls::conn::PlaintextSink>::write_vectored") {
			return rustTLSWriteVectored, true
		}
	}

	if strings.HasPrefix(name, "tokio::runtime::task::raw::poll::<") || name == "tokio::runtime::task::raw::poll" {
		return rustTaskPoll, true
	}

	if strings.HasPrefix(name, "tokio::runtime::task::raw::dealloc::<") || name == "tokio::runtime::task::raw::dealloc" {
		return rustTaskDealloc, true
	}

	if strings.HasPrefix(name, "<tokio::runtime::task::core::Cell<") && strings.HasSuffix(name, ">::new") {
		return rustTaskNew, true
	}

	// Only Hyper request envelopes have the large, indirectly passed ABI used
	// by the probes. Matching just Block<T> would also attach to unrelated queues.
	if strings.HasPrefix(name, "<tokio::sync::mpsc::block::Block<hyper::client::dispatch::Envelope<") {
		if strings.HasSuffix(name, ">::write::{closure#0}") {
			return rustHyperEnqueue, true
		}

		if strings.HasSuffix(name, ">::read::{closure#0}") {
			return rustHyperDequeue, true
		}
	}

	return 0, false
}

func (p rustProbeSymbols) layoutChannels() []string {
	var channels []string
	for _, name := range p.channels {
		for _, kind := range []rustProbeKind{rustHyperEnqueue, rustHyperSend, rustHyperChanSend, rustHyperFindBlock, rustHyperRequestSend} {
			if len(p.channelProbes[name][kind]) > 0 {
				channels = append(channels, name)
				break
			}
		}
	}

	return channels
}
