// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// offsets_test.go checks version inference, partial layout selection, channel
// fallback identities, profile deduplication, and JSON database round trips.

package rustexec

import (
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
		Channels:     map[string]MessageLayout{"Envelope<A>": {ListIndex: 16, SlotMask: 31, TxPointer: 272, RxPointer: 272}},
		CrateSymbols: map[string]map[string]string{"tokio": {"CsKnown_5tokio": "1.54.1"}},
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
	build := Build{Arch: p.Arch, CompilerCommit: p.CompilerCommit, CrateIDs: map[string][]string{"tokio": {"CsKnown_5tokio"}}}
	got := database.InferBuild(build)
	require.Equal(t, p.Rustc, got.Rustc)
	require.Equal(t, []string{"1.54.1"}, got.Crates["tokio"])
	withoutComment := build
	withoutComment.CompilerCommit = ""
	require.Equal(t, p.Rustc, database.InferBuild(withoutComment).Rustc)
	build.CrateIDs["tokio"] = append(build.CrateIDs["tokio"], "CsUnknown_5tokio")
	require.Empty(t, database.InferBuild(build).Crates["tokio"], "partial fingerprint matches cannot identify an entire crate set")
	other := sampleProfile()
	other.CrateSymbols = map[string]map[string]string{"tokio": {"CsKnown_5tokio": "1.53.3"}}
	database.Profiles = append(database.Profiles, other)
	build.CrateIDs["tokio"] = []string{"CsKnown_5tokio"}
	require.Empty(t, database.InferBuild(build).Crates["tokio"], "conflicting fingerprints must fail closed")
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
