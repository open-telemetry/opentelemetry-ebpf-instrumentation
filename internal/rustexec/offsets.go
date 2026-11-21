// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// offsets.go defines the build identities, offset profiles, and database schema.
// It identifies compiler and crate versions from ELF metadata: compiler comments,
// source paths, and cargo-auditable dependency lists.

package rustexec // import "go.opentelemetry.io/obi/internal/rustexec"

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
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
	CompilerCommit string `json:",omitempty"`
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
}

// cargo-auditable's embedded dependency list, see
// https://github.com/rust-secure-code/cargo-auditable/blob/master/PARSING.md
const (
	rustAuditableSection = ".dep-v0"
	// the decompressed size limit PARSING.md recommends against zip bombs
	rustAuditableMaxBytes = 8 << 20
)

var (
	rustTrackedCrates = []string{"tokio", "reqwest", "hyper", "h2", "rustls", "http", "bytes"}
	// Cargo registry and vendor directories follow a separator, Bazel rules_rust
	// repositories are named <hub>__<crate>-<version>
	rustCrateVersion = regexp.MustCompile(
		`(?:^|[/\\ ]|__)(` + strings.Join(rustTrackedCrates, "|") + `)-([0-9]+\.[0-9]+\.[0-9]+)[/\\]`)
	rustCompilerVersion = regexp.MustCompile(`rustc version ([0-9]+\.[0-9]+\.[0-9]+) \(`)
	rustCompilerCommit  = regexp.MustCompile(`[/\\]rustc[/\\]([0-9a-f]{40})[/\\]`)
)

type rustAuditablePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// a string, or an {"Other": ...} object for unrecognized sources
	Source json.RawMessage `json:"source"`
	Kind   string          `json:"kind"`
}

func ReadBuild(f *elf.File) (Build, error) {
	b := Build{Crates: map[string][]string{}}
	switch f.Machine {
	case elf.EM_X86_64:
		b.Arch = "amd64"
	case elf.EM_AARCH64:
		b.Arch = "arm64"
	default:
		return b, errors.New("unsupported Rust ELF architecture")
	}

	for _, section := range f.Sections {
		if section.Name == rustAuditableSection {
			data, err := section.Data()
			if err != nil {
				return b, err
			}

			if err := addAuditableCrateVersions(b.Crates, data); err != nil {
				return b, fmt.Errorf("reading %s: %w", rustAuditableSection, err)
			}

			continue
		}

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

		addPathCrateVersions(b.Crates, data)
	}

	return b, nil
}

func addCrateVersion(crates map[string][]string, name, version string) {
	if !slices.Contains(crates[name], version) {
		crates[name] = append(crates[name], version)
	}
}

func addPathCrateVersions(crates map[string][]string, data []byte) {
	for _, match := range rustCrateVersion.FindAllSubmatch(data, -1) {
		addCrateVersion(crates, string(match[1]), string(match[2]))
	}
}

// Only registry packages linked at runtime are recorded: git and local packages
// can carry a published version number over different sources.
func addAuditableCrateVersions(crates map[string][]string, compressed []byte) error {
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return err
	}

	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, rustAuditableMaxBytes+1))
	if err != nil {
		return err
	}

	if len(data) > rustAuditableMaxBytes {
		return errors.New("dependency list exceeds the size limit")
	}

	var list struct {
		Packages []rustAuditablePackage `json:"packages"`
	}

	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	for _, pkg := range list.Packages {
		var source string
		if json.Unmarshal(pkg.Source, &source) != nil || source != "crates.io" && source != "registry" {
			continue
		}

		if pkg.Kind == "build" || !slices.Contains(rustTrackedCrates, pkg.Name) {
			continue
		}

		addCrateVersion(crates, pkg.Name, pkg.Version)
	}

	return nil
}

// InferBuild fills in a compiler version the binary's comment section omits.
// Toolchain builds share one standard-library commit, so its source paths
// identify the compiler of any binary built with that toolchain.
func (d Database) InferBuild(build Build) Build {
	if build.Rustc != "" || build.CompilerCommit == "" {
		return build
	}

	for _, profile := range d.Profiles {
		if profile.Arch == build.Arch && profile.CompilerCommit == build.CompilerCommit {
			build.Rustc = profile.Rustc
			break
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
