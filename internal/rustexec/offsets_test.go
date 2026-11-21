// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// offsets_test.go checks version detection and inference, partial layout
// selection, channel fallback identities, profile deduplication, and JSON
// database round trips.

package rustexec

import (
	"bytes"
	"compress/zlib"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func sampleProfile() Profile {
	return Profile{
		Arch: "amd64", Rustc: "1.100.0", CompilerCommit: "compiler-commit", Crates: map[string][]string{
			"http": {"1.5.0"}, "bytes": {"1.12.1"}, "h2": {"0.4.20"}, "rustls": {"0.23.46"},
			"tokio": {"1.54.1"}, "hyper": {"1.12.0"}, "reqwest": {"0.13.5"},
		}, Config: Layouts{VecPtr: 8, VecLen: 16, HTTP1: 1, HTTP2: 1, Rustls: 1, H2StreamID: 280, TLSPlaintext: 80},
		Channels: map[string]MessageLayout{"Envelope<A>": {ListIndex: 16, SlotMask: 31, TxPointer: 272, RxPointer: 272}},
	}
}

func TestPartialLayouts(t *testing.T) {
	p := sampleProfile()
	build := Build{Arch: p.Arch, Rustc: p.Rustc, Crates: sampleProfile().Crates}
	build.Crates["rustls"] = []string{"0.23.47"}
	config, err := SelectLayouts(build, Database{Profiles: []Profile{p}}, "Envelope<A>")
	require.ErrorContains(t, err, "rustls 0.23.47")
	require.Zero(t, config.Rustls)
	require.EqualValues(t, 1, config.HTTP1)
	require.EqualValues(t, 1, config.HTTP2)
	require.EqualValues(t, MessageCallback|MessageList, config.Message)
}

func TestCallbackAlternatives(t *testing.T) {
	p := sampleProfile()
	p.Channels["Envelope<B>"] = MessageLayout{ListIndex: 16, SlotMask: 31, TxPointer: 264, RxPointer: 264}
	config, err := SelectLayouts(Build{Arch: p.Arch, Rustc: p.Rustc, Crates: p.Crates}, Database{Profiles: []Profile{p}}, "Envelope<A>", "Envelope<B>")
	require.NoError(t, err)
	require.EqualValues(t, MessageList, config.Message, "different callbacks must retain the common queue-slot fallback")
	config, err = SelectLayouts(Build{Arch: p.Arch, Rustc: p.Rustc, Crates: p.Crates}, Database{Profiles: []Profile{p}}, "Envelope<UnrecordedBody>")
	require.NoError(t, err)
	require.EqualValues(t, MessageList, config.Message)
}

func TestRequestIdentityFallback(t *testing.T) {
	p := sampleProfile()
	first := p.Channels["Envelope<A>"]
	first.Request, first.RxHeaders = true, 48
	p.Channels["Envelope<A>"] = first
	second := first
	second.TxPointer, second.RxPointer = 264, 264
	p.Channels["Envelope<B>"] = second
	build := Build{Arch: p.Arch, Rustc: p.Rustc, Crates: p.Crates}
	config, err := SelectLayouts(build, Database{Profiles: []Profile{p}}, "Envelope<A>", "Envelope<B>")
	require.NoError(t, err)
	require.EqualValues(t, MessageList|MessageRequest, config.Message,
		"different callback layouts must retain a compatible request identity")
	require.EqualValues(t, 48, config.MessageRxHeaders)

	second.RxHeaders = 56
	p.Channels["Envelope<B>"] = second
	config, err = SelectLayouts(build, Database{Profiles: []Profile{p}}, "Envelope<A>", "Envelope<B>")
	require.NoError(t, err)
	require.EqualValues(t, MessageList, config.Message,
		"ambiguous request layouts must retain only the safe queue-slot fallback")
}

func TestProtocolLayoutDependencies(t *testing.T) {
	t.Run("missing headers disable HTTP decoding", func(t *testing.T) {
		p := sampleProfile()
		p.Config.HTTP1 = 0
		p.Config.H2Server = 1
		config, err := SelectLayouts(Build{Arch: p.Arch, Rustc: p.Rustc, Crates: p.Crates}, Database{Profiles: []Profile{p}})

		require.ErrorContains(t, err, "Rust HTTP headers")
		require.Zero(t, config.HTTP1)
		require.Zero(t, config.HTTP2)
		require.Zero(t, config.H2Server)
		require.EqualValues(t, 1, config.Rustls)
	})

	t.Run("ambiguous vectors preserve decoded request identities", func(t *testing.T) {
		p := sampleProfile()
		channel := p.Channels["Envelope<A>"]
		channel.Request, channel.RxHeaders = true, 48
		p.Channels["Envelope<A>"] = channel
		other := p
		other.Config.VecPtr = 0
		config, err := SelectLayouts(Build{Arch: p.Arch, Rustc: p.Rustc, Crates: p.Crates},
			Database{Profiles: []Profile{p, other}}, "Envelope<A>")

		require.ErrorContains(t, err, "Rust vectors has ambiguous recorded layouts")
		require.Zero(t, config.HTTP1)
		require.EqualValues(t, 1, config.HTTP2)
		require.EqualValues(t, 1, config.Rustls)
		require.EqualValues(t, MessageCallback|MessageList|MessageRequest, config.Message)
		require.EqualValues(t, 48, config.MessageRxHeaders)
	})
}

func TestOptionalRustlsBinding(t *testing.T) {
	p := sampleProfile()
	p.Config.TLSSendable, p.Config.TLSEncrypter = 24, 32
	other := p
	other.Config.TLSSendable = 40
	config, err := SelectLayouts(Build{Arch: p.Arch, Rustc: p.Rustc, Crates: p.Crates}, Database{Profiles: []Profile{p, other}})

	require.NoError(t, err, "ambiguous optional binding must not disable plaintext capture")
	require.EqualValues(t, 1, config.Rustls)
	require.Equal(t, p.Config.TLSPlaintext, config.TLSPlaintext)
	require.Zero(t, config.TLSSendable)
	require.Zero(t, config.TLSEncrypter)
}

func TestUnavailableChannelLayouts(t *testing.T) {
	p := sampleProfile()
	build := Build{Arch: p.Arch, Rustc: p.Rustc, Crates: sampleProfile().Crates}
	build.Crates["tokio"] = []string{"unrecorded"}
	config, err := SelectLayouts(build, Database{Profiles: []Profile{p}}, "Envelope<A>")

	require.ErrorContains(t, err, "Tokio channel slots")
	require.ErrorContains(t, err, "Hyper callback Envelope<A>")
	require.ErrorContains(t, err, "Hyper request identity Envelope<A>")
	require.Zero(t, config.Message)
	require.EqualValues(t, 1, config.HTTP1)
	require.EqualValues(t, 1, config.HTTP2)
	require.EqualValues(t, 1, config.Rustls)
}

func TestVersionInference(t *testing.T) {
	p := sampleProfile()
	database := Database{Profiles: []Profile{p}}
	build := Build{Arch: p.Arch, CompilerCommit: p.CompilerCommit}
	require.Equal(t, p.Rustc, database.InferBuild(build).Rustc)
	build.CompilerCommit = "unrecorded-commit"
	require.Empty(t, database.InferBuild(build).Rustc)
}

func TestCrateVersionPaths(t *testing.T) {
	crates := map[string][]string{}
	// Rust packs string literals without separators
	addPathCrateVersions(crates, []byte(
		"/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.54.1/src/runtime/park.rs"+
			"external/crates__h2-0.4.20/src/proto/streams/send.rs"+
			"external/rules_rust++crate+crates__hyper-1.12.0/src/client/conn/http1.rs"+
			"external/crates__lambda_http-0.13.0/src/lib.rs"+
			"vendor/tower-http-0.6.2/src/lib.rs"))
	require.Equal(t, map[string][]string{"tokio": {"1.54.1"}, "h2": {"0.4.20"}, "hyper": {"1.12.0"}}, crates)
}

func TestAuditableCrateVersions(t *testing.T) {
	list := `{"format":1,"packages":[
		{"name":"app","version":"0.1.0","source":"local","root":true,"dependencies":[1,2,3,4,5,6]},
		{"name":"tokio","version":"1.54.1","source":"crates.io"},
		{"name":"http","version":"1.3.1","source":"registry","kind":"runtime"},
		{"name":"bytes","version":"1.10.1","source":"crates.io","kind":"build"},
		{"name":"hyper","version":"1.12.0","source":"git"},
		{"name":"rustls","version":"0.23.46","source":{"Other":"sparse+https://example.com/"}},
		{"name":"serde","version":"1.0.219","source":"crates.io"}]}`
	crates := map[string][]string{"tokio": {"1.54.1"}}
	require.NoError(t, addAuditableCrateVersions(crates, zlibCompress(t, []byte(list))))
	require.Equal(t, map[string][]string{"tokio": {"1.54.1"}, "http": {"1.3.1"}}, crates)

	oversized := append([]byte(`{"packages":[]}`), bytes.Repeat([]byte(" "), rustAuditableMaxBytes)...)
	require.ErrorContains(t, addAuditableCrateVersions(crates, zlibCompress(t, oversized)), "size limit")
	require.Error(t, addAuditableCrateVersions(crates, []byte("not zlib")))
}

func zlibCompress(t *testing.T, data []byte) []byte {
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	_, err := writer.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return compressed.Bytes()
}

func TestDatabaseRoundTrip(t *testing.T) {
	database := Database{Measurements: map[string]string{"fixture": "digest"}}
	p := sampleProfile()
	database.Add(p)
	database.Add(p)
	require.Len(t, database.Profiles, 1)
	path := filepath.Join(t.TempDir(), "offsets.json")
	require.NoError(t, database.Write(path))
	loaded, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, database, loaded)
}
