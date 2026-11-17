// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// offsets.go defines the build identities, offset profiles, and database schema.
// It identifies compiler and crate versions from ELF metadata and symbols, using
// recorded fingerprints when version strings are unavailable.

package rustexec // import "go.opentelemetry.io/obi/internal/rustexec"

import (
	"debug/elf"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Layouts struct {
	VecPtr              uint32
	VecLen              uint32
	VecCap              uint32
	BytesPtr            uint32
	BytesLen            uint32
	BytesCap            uint32
	LimitInner          uint32
	LimitRemaining      uint32
	H2StreamID          uint32 `json:"H2StreamId"`
	H2Fields            uint32
	H2Method            uint32
	RequestHeaders      uint32
	HeaderEntries       uint32
	HeaderCount         uint32
	BucketSize          uint32
	NamePtr             uint32
	NameLen             uint32
	ValuePtr            uint32
	ValueLen            uint32
	ReaderBuffer        uint32
	TLSCommon           uint32 `json:"TlsCommon"`
	TLSClientDeframer   uint32 `json:"TlsClientDeframer"`
	TLSServerDeframer   uint32 `json:"TlsServerDeframer"`
	TLSDeframerPointer  uint32 `json:"TlsDeframerPointer"`
	TLSDeframerUsed     uint32 `json:"TlsDeframerUsed"`
	TLSPlaintext        uint32 `json:"TlsPlaintext"`
	TLSDecrypter        uint32 `json:"TlsDecrypter"`
	TLSEncrypter        uint32 `json:"TlsEncrypter"`
	TLSSendable         uint32 `json:"TlsSendable"`
	H2StoreStreamID     uint32 `json:"H2StoreStreamId"`
	H2StreamRefID       uint32 `json:"H2StreamRefId"`
	H2Prioritize        uint32
	ListHead            uint32
	ListIndex           uint32
	SlotMask            uint32
	MessageTxTag        uint32
	MessageTxSome       uint32
	MessageTxPointer    uint32
	MessageRxTag        uint32
	MessageRxSome       uint32
	MessageRxPointer    uint32
	MessageRxHeaders    uint32
	HTTP1               uint8 `json:"Http1"`
	HTTP2               uint8 `json:"Http2"`
	Rustls              uint8
	Inject              uint8
	H2Server            uint8
	Message             uint8
	TLSExternalDeframer uint8 `json:"TlsExternalDeframer"`
	H2Hpack             uint8
}

type MessageLayout struct {
	ListHead  uint32
	ListIndex uint32
	SlotMask  uint32
	TxTag     uint32
	TxSome    uint32
	TxPointer uint32
	RxTag     uint32
	RxSome    uint32
	RxPointer uint32
	RxHeaders uint32
	Request   bool `json:",omitempty"`
}

type Profile struct {
	Arch           string
	Rustc          string
	Crates         map[string][]string
	Config         Layouts
	Channels       map[string]MessageLayout
	CompilerCommit string                       `json:",omitempty"`
	CrateSymbols   map[string]map[string]string `json:",omitempty"`
}

type Database struct {
	Profiles     []Profile         `json:"profiles"`
	Measurements map[string]string `json:"measurements,omitempty"`
}

type Build struct {
	Arch           string
	Rustc          string
	Crates         map[string][]string
	CompilerCommit string
	CrateIDs       map[string][]string
}

var (
	rustCrateVersion    = regexp.MustCompile(`(?:^|[/\\ ])(tokio|reqwest|hyper|h2|rustls|http|bytes)-([0-9]+\.[0-9]+\.[0-9]+)[/\\]`)
	rustCompilerVersion = regexp.MustCompile(`rustc version ([0-9]+\.[0-9]+\.[0-9]+) \(`)
	rustCompilerCommit  = regexp.MustCompile(`[/\\]rustc[/\\]([0-9a-f]{40})[/\\]`)
	rustCrateID         = regexp.MustCompile(`Cs[0-9A-Za-z]+_([0-9]+)(tokio|reqwest|hyper|h2|rustls|http|bytes)`)
)

func ReadBuild(f *elf.File) (Build, error) {
	b := Build{Crates: map[string][]string{}, CrateIDs: map[string][]string{}}
	switch f.Machine {
	case elf.EM_X86_64:
		b.Arch = "amd64"
	case elf.EM_AARCH64:
		b.Arch = "arm64"
	default:
		return b, errors.New("unsupported Rust ELF architecture")
	}

	for _, section := range f.Sections {
		if section.Name != ".comment" && !strings.HasPrefix(section.Name, ".rodata") {
			continue
		}

		data, err := section.Data()
		if err != nil {
			return b, err
		}

		if version := rustCompilerVersion.FindSubmatch(data); len(version) > 0 {
			b.Rustc = string(version[1])
		}

		if commit := rustCompilerCommit.FindSubmatch(data); len(commit) > 0 {
			b.CompilerCommit = string(commit[1])
		}

		for _, match := range rustCrateVersion.FindAllSubmatch(data, -1) {
			name, version := string(match[1]), string(match[2])
			if !slices.Contains(b.Crates[name], version) {
				b.Crates[name] = append(b.Crates[name], version)
			}
		}
	}

	symbols, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return b, err
	}

	for _, symbol := range symbols {
		if !strings.HasPrefix(symbol.Name, "_R") {
			continue
		}

		for _, match := range rustCrateID.FindAllStringSubmatch(symbol.Name, -1) {
			length, _ := strconv.Atoi(match[1])
			name := match[2]
			if length == len(name) && !slices.Contains(b.CrateIDs[name], match[0]) {
				b.CrateIDs[name] = append(b.CrateIDs[name], match[0])
			}
		}
	}

	return b, nil
}

func (d Database) InferBuild(build Build) Build {
	if build.Rustc == "" && build.CompilerCommit != "" {
		for _, profile := range d.Profiles {
			if profile.Arch == build.Arch && profile.CompilerCommit == build.CompilerCommit {
				build.Rustc = profile.Rustc
				break
			}
		}
	}

	if build.Rustc == "" {
		compilers := map[string]bool{}
		for _, profile := range d.Profiles {
			if profile.Arch != build.Arch {
				continue
			}

			for name, ids := range build.CrateIDs {
				for _, id := range ids {
					if profile.CrateSymbols[name][id] != "" {
						compilers[profile.Rustc] = true
					}
				}
			}
		}

		if len(compilers) == 1 {
			for compiler := range compilers {
				build.Rustc = compiler
			}
		}
	}

	crates := make(map[string][]string, len(build.Crates))
	for name, versions := range build.Crates {
		crates[name] = slices.Clone(versions)
	}

	build.Crates = crates
	for name, ids := range build.CrateIDs {
		if len(build.Crates[name]) != 0 {
			continue
		}

		var versions []string
		complete := true
		for _, id := range ids {
			version := ""
			for _, profile := range d.Profiles {
				if profile.Arch != build.Arch || profile.Rustc != build.Rustc {
					continue
				}

				candidate := profile.CrateSymbols[name][id]
				if candidate != "" && version != "" && candidate != version {
					complete = false
				}

				if candidate != "" {
					version = candidate
				}
			}

			if version == "" {
				complete = false
			} else if !slices.Contains(versions, version) {
				versions = append(versions, version)
			}
		}

		if complete {
			build.Crates[name] = versions
		}
	}

	return build
}

func rustCrateMatches(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}

	return false
}
