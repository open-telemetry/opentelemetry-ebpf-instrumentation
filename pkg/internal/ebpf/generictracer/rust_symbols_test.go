// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	"encoding/json"
	"os"
	osexec "os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/ianlancetaylor/demangle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/rustexec"
)

func TestRustSymbolSelection(t *testing.T) {
	for name, kind := range map[string]rustProbeKind{
		"tokio::runtime::task::raw::poll::<T, S>":                                                                 rustTaskPoll,
		"<tokio::runtime::task::core::Cell<T, S>>::new":                                                           rustTaskNew,
		"<tokio::runtime::thread_pool::Spawner>::spawn::<F>":                                                      rustTaskSpawn,
		"<tokio::runtime::basic_scheduler::Spawner>::spawn::<F>":                                                  rustTaskSpawn,
		"<tokio::runtime::thread_pool::worker::Shared>::schedule":                                                 rustTaskSchedule,
		"<alloc::sync::Arc<tokio::runtime::basic_scheduler::Shared> as tokio::runtime::task::Schedule>::schedule": rustTaskSchedule,
		"<h2::proto::streams::send::Send>::send_headers::<B>":                                                     rustH2SendHeaders,
		"<h2::proto::streams::send::Send>::buffer_pending::<T, B>":                                                rustH2BufferPending,
		"<rustls::conn::ConnectionCommon<T> as rustls::conn::PlaintextSink>::write":                               rustTLSWrite,
		"<rustls::vecbuf::ChunkVecBuffer>::read":                                                                  rustTLSRead,
		"<rustls::conn::CommonState>::write_tls":                                                                  rustTLSFlush,
		"<rustls::conn::ConnectionCommon<rustls::client::client_conn::ClientConnectionData>>::write_tls":          rustTLSFlush,
	} {
		actual, ok := rustSymbolKind(name)
		assert.True(t, ok, name)
		assert.Equal(t, kind, actual, name)
	}
	for _, name := range []string{
		"core::ptr::drop_glue::<tokio::runtime::task::raw::RawTask>",
		"<tokio::runtime::task::raw::RawTask>::poll",
		"<tokio::runtime::task::core::Cell<T, S>>::new::{closure#0}",
		"<tokio::runtime::thread_pool::Spawner>::spawn::<F>::{closure#0}",
		"<tokio::runtime::thread_pool::worker::Shared>::schedule::{closure#0}",
		"<tokio::sync::mpsc::block::Block<u8>>::write::{closure#0}",
		"<tokio::sync::mpsc::block::Block<hyper::client::dispatch::Envelope<T, U>>>::read",
		"<h2::proto::streams::send::Send>::send_headers::<B>::{closure#0}",
	} {
		_, ok := rustSymbolKind(name)
		assert.False(t, ok, name)
	}
}

func TestResolveRustBinary(t *testing.T) {
	path := os.Getenv("OBI_RUST_TEST_BINARY")
	if path == "" {
		t.Skip("set OBI_RUST_TEST_BINARY to an unstripped Tokio/reqwest fixture")
	}
	f, err := elf.Open(path)
	require.NoError(t, err)
	defer f.Close()
	probes, err := resolveRustProbes(f)
	require.NoError(t, err)
	require.True(t, probes.hasTokio)
	for kind, offsets := range probes.addresses {
		t.Logf("kind %d: %d offsets", kind, len(offsets))
		if rustProbeKind(kind) == rustTaskPoll || rustProbeKind(kind) == rustTaskDealloc {
			require.NotEmpty(t, offsets, "probe kind %d", kind)
		}
	}
}

func TestRejectUnsupportedRustBinary(t *testing.T) {
	path := os.Getenv("OBI_RUST_UNSUPPORTED_BINARY")
	if path == "" {
		path = "/proc/self/exe"
	}
	f, err := elf.Open(path)
	require.NoError(t, err)
	defer f.Close()
	probes, err := resolveRustProbes(f)
	require.Error(t, err)
	assert.Equal(t, rustProbeSymbols{}, probes)
}

func TestRustProtocolLayouts(t *testing.T) {
	path := os.Getenv("OBI_RUST_TLS_TEST_BINARY")
	if path == "" {
		t.Skip("set OBI_RUST_TLS_TEST_BINARY to a fixture compiled with --features=tls")
	}
	f, err := elf.Open(path)
	require.NoError(t, err)
	defer f.Close()
	probes, err := resolveRustProbes(f)
	require.NoError(t, err)
	config, err := resolveRustProtocolLayouts(f, probes.layoutChannels()...)
	require.NoError(t, err)
	_, err = f.DWARF()
	require.Error(t, err, "protocol validation must use a production fixture without DWARF")
	t.Logf("Rust protocol layouts: %+v", config)
	require.NotEqual(t, config.VecLen, config.VecPtr)
	require.NotZero(t, config.BucketSize)
	require.NotZero(t, config.Message)
	require.EqualValues(t, 1, config.Http1)
	require.EqualValues(t, 1, config.Http2)
	if os.Getenv("OBI_RUST_TEST_TLS") != "" || os.Getenv("OBI_RUST_TEST_SERVER") != "" {
		require.EqualValues(t, 1, config.Rustls)
	}
}

func TestRustOffsetSelection(t *testing.T) {
	var database rustexec.Database
	require.NoError(t, json.Unmarshal(rustOffsetData, &database))
	for _, arch := range []string{"amd64", "arm64"} {
		for _, compiler := range []string{"1.97.1", "1.98.1", "1.99.1", "1.100.0"} {
			for _, version := range []string{"0.20.9", "0.21.12", "0.22.4", "0.23.46"} {
				build := rustexec.Build{Arch: arch, Rustc: compiler, Crates: map[string][]string{
					"rustls": {version}, "http": {"1.5.0"}, "h2": {"0.4.20"}, "bytes": {"1.12.1"},
				}}
				config, err := selectRustProtocolLayouts(build, database)
				require.NoError(t, err)
				require.EqualValues(t, 1, config.Rustls, "%s/%s", arch, version)
				require.EqualValues(t, 1, config.Http2)
				require.NotZero(t, config.H2Method)
				require.NotZero(t, config.TlsSendable)
				require.NotZero(t, config.TlsEncrypter)
			}
		}
	}
	build := rustexec.Build{Arch: "amd64", Rustc: "1.100.0", Crates: map[string][]string{
		"rustls": {"0.22.4", "0.23.46"},
	}}
	_, err := selectRustProtocolLayouts(build, database)
	require.ErrorContains(t, err, "ambiguous")
	build.Rustc = "unknown"
	_, err = selectRustProtocolLayouts(build, database)
	require.ErrorContains(t, err, "no recorded offset profile")
	build.Rustc = "1.100.0"
	build.Crates = map[string][]string{"rustls": {"0.23.47"}}
	config, err := selectRustProtocolLayouts(build, database)
	require.ErrorContains(t, err, "no recorded offset profile")
	require.Zero(t, config.Rustls)
}

func TestRustReleaseIdentity(t *testing.T) {
	path := os.Getenv("OBI_RUST_TEST_BINARY")
	if path == "" {
		t.Skip("set a release fixture to verify version inference")
	}
	f, err := elf.Open(path)
	require.NoError(t, err)
	defer f.Close()
	build, err := rustexec.ReadBuild(f)
	require.NoError(t, err)
	if compiler := os.Getenv("OBI_RUST_TEST_EXPECTED_COMPILER"); compiler != "" {
		require.Equal(t, compiler, build.Rustc)
	}
	var database rustexec.Database
	require.NoError(t, json.Unmarshal(rustOffsetData, &database))
	inferred := database.InferBuild(rustexec.Build{Arch: build.Arch, CompilerCommit: build.CompilerCommit, CrateIDs: build.CrateIDs})
	require.Equal(t, build.Rustc, inferred.Rustc)
	for _, name := range []string{"tokio", "reqwest", "hyper"} {
		if expected := os.Getenv("OBI_RUST_TEST_EXPECTED_" + strings.ToUpper(name)); expected != "" {
			require.Contains(t, build.Crates[name], expected, name)
		}
	}
	for name, versions := range build.Crates {
		if len(versions) == 1 {
			require.Equal(t, versions, inferred.Crates[name], "%s must be identifiable without Cargo source paths", name)
		}
	}
}

func TestPrepareRustAlternativeFixture(t *testing.T) {
	output, group := os.Getenv("OBI_RUST_STRIP_OUTPUT"), os.Getenv("OBI_RUST_STRIP_GROUP")
	if output == "" || group == "" {
		t.Skip("set the alternative fixture output and hook group")
	}
	path := os.Getenv("OBI_RUST_TEST_BINARY")
	f, err := elf.Open(path)
	require.NoError(t, err)
	probes, err := resolveRustProbes(f)
	require.NoError(t, err)
	groups := map[string][]rustProbeKind{
		"poll":               {rustTaskPoll},
		"allocation":         {rustTaskNew, rustTaskRawNew, rustTaskBind},
		"channel":            {rustHyperEnqueue, rustHyperDequeue, rustHyperSend, rustHyperChanSend, rustHyperRequestSend, rustHyperReceive},
		"h2-hpack":           {rustH2HPACK},
		"http1":              {rustHTTP1Headers, rustHTTP1HeadersOriginal},
		"channels-missing":   {rustHyperEnqueue, rustHyperDequeue, rustHyperSend, rustHyperChanSend, rustHyperRequestSend, rustHyperReceive, rustHyperFindBlock, rustHyperPop},
		"tasks-missing":      {rustTaskPoll, rustTaskHarnessPoll},
		"tasks-missing-h2":   {rustTaskPoll, rustTaskHarnessPoll},
		"h2-server":          {rustH2TakeStreamRequest, rustH2TakeRequest},
		"tls-client-process": {rustTLSClientProcess, rustTLSClientLegacyProcess, rustTLSServerProcess, rustTLSServerLegacyProcess},
		"tls-server-process": {rustTLSClientProcess, rustTLSClientLegacyProcess, rustTLSServerProcess, rustTLSServerLegacyProcess},
	}
	for kind := rustH2SendHeaders; kind <= rustH2HPACK; kind++ {
		groups["h2"] = append(groups["h2"], kind)
	}
	groups["channels-missing-h2"] = groups["channels-missing"]
	kinds, ok := groups[group]
	require.True(t, ok, group)
	if group == "poll" {
		require.NotEmpty(t, probes.addresses[rustTaskHarnessPoll], "the poll fallback must exist")
	}
	if group == "allocation" {
		require.NotEmpty(t, probes.addresses[rustTaskSpawn])
		require.NotEmpty(t, probes.addresses[rustTaskSchedule])
	}
	if group == "channel" {
		if len(probes.addresses[rustHyperFindBlock]) == 0 || len(probes.addresses[rustHyperPop]) == 0 {
			t.Skip("this compiler inlined the queue-slot alternative; the missing-channel case verifies partial support")
		}
	}
	if group == "h2-hpack" {
		require.NotEmpty(t, probes.addresses[rustH2Encode])
	}
	if strings.HasPrefix(group, "tls-") {
		require.Positive(t, len(probes.addresses[rustTLSFlush])+len(probes.addresses[rustTLSFlushBuffer]),
			"the encrypted I/O binding fallback must exist")
	}
	symbols, err := f.Symbols()
	require.NoError(t, err)
	var arguments []string
	for _, symbol := range symbols {
		decoded, err := demangle.ToString(symbol.Name, demangle.NoClones, demangle.MaxLength(16))
		if err != nil {
			continue
		}
		kind, ok := rustSymbolKind(decoded)
		if ok && slices.Contains(kinds, kind) {
			arguments = append(arguments, "--strip-symbol="+symbol.Name)
		}
	}
	require.NoError(t, f.Close())
	if !strings.HasPrefix(group, "tls-") {
		require.NotEmpty(t, arguments, "the fixture must exercise actual missing hooks")
	}
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(output, data, 0o755))
	if len(arguments) == 0 {
		t.Log("the packet-processing wrappers were already inlined")
		return
	}
	arguments = append(arguments, output)
	result, err := osexec.Command("objcopy", arguments...).CombinedOutput()
	require.NoError(t, err, "%s", result)
}
